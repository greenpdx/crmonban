//! Layer-2 attack monitor — the passive "raw, not IP" detection plane.
//!
//! The packet engine and NFQUEUE operate at L3 (IP): NFQUEUE hands userspace an
//! IP payload with no Ethernet frame, and `core::parse_ethernet_packet` discards
//! every non-IP frame (it requires an IP `Layer3`). So ARP — and the broadcast
//! L2 attack surface — never reaches the `layer234` L2 trackers through that path.
//!
//! This monitor opens its own raw frame capture (libpcap, `DLT_EN10MB`) on the
//! interface and feeds the `layer234` L2/L3 state trackers that were implemented
//! but never wired into any pipeline:
//!   * ARP spoofing       — Ethernet/ARP frames (ethertype 0x0806)
//!   * DHCP starvation /
//!     rogue DHCP server  — IPv4/UDP ports 67/68
//!   * IPv6 RA spoofing /
//!     RA flood           — IPv6/ICMPv6 type 134
//!
//! Detections are emitted as `MonitorEvent`s into the same channel as every
//! other detector, so the two capture planes (this one + the inline nfqueue
//! engine) converge on the shared ban/alert store — no packet-level
//! synchronisation, just a shared sink.

use std::net::IpAddr;
use std::time::Duration;

use anyhow::Result;
use chrono::Utc;
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcap::Capture;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::layer234::{
    ArpPacket, ArpStateTracker, DhcpPacket, DhcpStateTracker, Icmpv6Ra, RaStateTracker,
};
use crate::models::{AttackEvent, AttackEventType};
use crate::monitor::MonitorEvent;

const ETHERTYPE_ARP: u16 = 0x0806;
const ETH_HDR_LEN: usize = 14;
const ICMPV6_TYPE_RA: u8 = 134;

/// Configuration for the L2 monitor.
pub struct L2MonitorConfig {
    /// Interface to capture raw frames on (e.g. "enp5s0").
    pub interface: String,
    /// IP→MAC binding changes before an ARP spoof alert fires.
    pub arp_change_threshold: u32,
    /// Unique client MACs in the window before a DHCP-starvation alert fires.
    pub dhcp_starvation_threshold: u32,
    /// Distinct routers before an RA-flood alert fires.
    pub ra_flood_threshold: u32,
}

impl Default for L2MonitorConfig {
    fn default() -> Self {
        Self {
            interface: "eth0".to_string(),
            arp_change_threshold: 2,
            dhcp_starvation_threshold: 50,
            ra_flood_threshold: 10,
        }
    }
}

/// The L2 trackers, owned by the capture loop.
struct L2Trackers {
    arp: ArpStateTracker,
    dhcp: DhcpStateTracker,
    ra: RaStateTracker,
}

/// Run the L2 monitor until the capture or the event channel closes.
///
/// The blocking libpcap loop runs on a dedicated blocking thread; detections
/// cross back to the daemon via the shared `event_tx`.
pub async fn start_l2_monitor(
    config: L2MonitorConfig,
    event_tx: mpsc::Sender<MonitorEvent>,
) -> Result<()> {
    info!(
        "Starting L2 monitor (ARP / DHCP / IPv6-RA) on interface {}",
        config.interface
    );

    let handle = tokio::task::spawn_blocking(move || -> Result<()> {
        // Frame-level capture: we need the Ethernet header (ethertype + MACs),
        // so this is the raw L2 path, not the IP-only nfqueue path. The snaplen
        // must be large enough for a full DHCP/BOOTP message (236 + options).
        let mut cap = Capture::from_device(config.interface.as_str())?
            .promisc(true)
            .snaplen(1500)
            .timeout(500)
            .open()?;

        info!("L2 monitor capture opened on {}", config.interface);

        let mut arp = ArpStateTracker::new();
        arp.set_change_threshold(config.arp_change_threshold);
        let mut dhcp = DhcpStateTracker::new();
        dhcp.set_starvation_threshold(config.dhcp_starvation_threshold);
        let mut ra = RaStateTracker::new();
        ra.set_flood_threshold(config.ra_flood_threshold);
        let mut trackers = L2Trackers { arp, dhcp, ra };

        loop {
            match cap.next_packet() {
                Ok(pkt) => {
                    for ev in inspect_frame(pkt.data, &mut trackers) {
                        // blocking_send: we're on a blocking thread, not in async.
                        if event_tx.blocking_send(ev).is_err() {
                            warn!("L2 monitor: event channel closed; stopping");
                            return Ok(());
                        }
                    }
                }
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(pcap::Error::NoMorePackets) => return Ok(()),
                Err(e) => {
                    warn!("L2 monitor capture error: {}", e);
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        }
    });

    handle.await??;
    Ok(())
}

/// Inspect one Ethernet frame; return any L2/L3 attack detections.
fn inspect_frame(frame: &[u8], t: &mut L2Trackers) -> Vec<MonitorEvent> {
    if frame.len() < ETH_HDR_LEN {
        return Vec::new();
    }

    // ARP is not IP, so etherparse's IP-oriented slicing won't carry it — handle
    // it directly off the ethertype.
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype == ETHERTYPE_ARP {
        return inspect_arp(&frame[ETH_HDR_LEN..], &mut t.arp);
    }

    // IPv4/UDP DHCP and IPv6/ICMPv6 RA ride normal IP framing.
    let sliced = match SlicedPacket::from_ethernet(frame) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    match (&sliced.net, &sliced.transport) {
        (Some(NetSlice::Ipv4(ipv4)), Some(TransportSlice::Udp(udp))) => {
            let (sp, dp) = (udp.source_port(), udp.destination_port());
            if sp == 67 || sp == 68 || dp == 67 || dp == 68 {
                let src_ip = ipv4.header().source_addr();
                return inspect_dhcp(udp.payload(), src_ip, &mut t.dhcp);
            }
            Vec::new()
        }
        (Some(NetSlice::Ipv6(ipv6)), Some(TransportSlice::Icmpv6(icmp6))) => {
            let bytes = icmp6.slice();
            if bytes.first().copied() == Some(ICMPV6_TYPE_RA) {
                let src_ip = ipv6.header().source_addr();
                return inspect_ra(bytes, src_ip, &mut t.ra);
            }
            Vec::new()
        }
        _ => Vec::new(),
    }
}

fn inspect_arp(arp_bytes: &[u8], arp: &mut ArpStateTracker) -> Vec<MonitorEvent> {
    let Some(pkt) = ArpPacket::parse(arp_bytes) else {
        return Vec::new();
    };
    let Some(alert) = arp.process_arp(&pkt) else {
        return Vec::new();
    };
    // ARP spoofing has no clean "attacker IP" to ban (the attacker asserts the
    // victim's IP with their own MAC), so this is an alert, not an auto-ban.
    let reason = format!(
        "ARP spoofing: {} rebound {} -> {} ({} changes)",
        alert.ip,
        fmt_mac(&alert.original_mac),
        fmt_mac(&alert.new_mac),
        alert.change_count,
    );
    vec![attack(
        IpAddr::V4(alert.ip),
        "l2_arp",
        "arp_spoofing",
        reason,
    )]
}

fn inspect_dhcp(payload: &[u8], src_ip: std::net::Ipv4Addr, dhcp: &mut DhcpStateTracker) -> Vec<MonitorEvent> {
    let Some(pkt) = DhcpPacket::parse(payload) else {
        return Vec::new();
    };
    let (starvation, rogue) = dhcp.process_dhcp(&pkt, src_ip);
    let mut out = Vec::new();
    if let Some(a) = starvation {
        let reason = format!(
            "DHCP starvation: {} unique MACs, {} requests in {}s",
            a.unique_macs, a.requests_in_window, a.window_seconds
        );
        // No single attacker IP for starvation; tag with the triggering src.
        out.push(attack(IpAddr::V4(src_ip), "l2_dhcp", "dhcp_starvation", reason));
    }
    if let Some(a) = rogue {
        let reason = format!(
            "Rogue DHCP server {} ({} offers)",
            a.server_ip, a.offers_count
        );
        out.push(attack(IpAddr::V4(a.server_ip), "l2_dhcp", "rogue_dhcp", reason));
    }
    out
}

fn inspect_ra(icmpv6: &[u8], src_ip: std::net::Ipv6Addr, ra: &mut RaStateTracker) -> Vec<MonitorEvent> {
    let Some(pkt) = Icmpv6Ra::parse(icmpv6) else {
        return Vec::new();
    };
    let (spoof, flood) = ra.process_ra(&pkt, src_ip);
    let mut out = Vec::new();
    if let Some(a) = spoof {
        let mac = a.src_mac.map(|m| fmt_mac(&m)).unwrap_or_else(|| "?".into());
        let reason = format!(
            "IPv6 RA spoofing from {} (mac {}, router_lifetime {})",
            a.src_ip, mac, a.router_lifetime
        );
        out.push(attack(IpAddr::V6(a.src_ip), "l2_ra", "ra_spoofing", reason));
    }
    if let Some(a) = flood {
        let reason = format!(
            "IPv6 RA flood: {} routers, {:.1} RA/s",
            a.unique_routers, a.ra_per_sec
        );
        out.push(attack(IpAddr::V6(src_ip), "l2_ra", "ra_flood", reason));
    }
    out
}

/// Build a logged Attack event for an L2 detection (alert, not auto-ban).
fn attack(ip: IpAddr, service: &str, kind: &str, reason: String) -> MonitorEvent {
    info!("L2 monitor: {}", reason);
    MonitorEvent::Attack(AttackEvent {
        id: None,
        ip,
        timestamp: Utc::now(),
        service: service.to_string(),
        event_type: AttackEventType::Other(kind.to_string()),
        details: Some(reason.clone()),
        log_line: reason,
    })
}

fn fmt_mac(m: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}
