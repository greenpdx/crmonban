//! Inline Layer-2 detection for the packet engine's af_packet capture.
//!
//! NFQUEUE delivers IP payloads with no Ethernet frame, and the core parser
//! drops every non-IP frame (`Packet` requires an IP `Layer3`), so ARP — and the
//! broadcast L2 attack surface — can never ride the engine's normal pipeline.
//! But the engine's **af_packet** capture already receives full Ethernet frames;
//! the IP parse just throws the non-IP ones away.
//!
//! This module is the tap at that seam: the same `layer234` L2 trackers the
//! standalone `l2_monitor` uses, but producing engine-native [`DetectionEvent`]s
//! so L2 attacks flow through the inline engine's own event bridge (record +
//! alert + the shared ban path) instead of a separate capture and channel. The
//! engine is the L2 detector — no sidecar socket.
//!
//! Detections:
//!   * ARP spoofing        — Ethernet/ARP frames (ethertype 0x0806)
//!   * DHCP starvation /
//!     rogue DHCP server   — IPv4/UDP ports 67/68
//!   * IPv6 RA spoofing /
//!     RA flood            — IPv6/ICMPv6 type 134
//!
//! L2 detections are **alerts, not auto-bans** (default `DetectionAction::Alert`):
//! ARP/RA spoofing has no clean attacker IP to ban — the attacker asserts a
//! victim's address — so the engine records and alerts, matching the sidecar's
//! behaviour. The bridge only escalates to a ban on a Drop/Reject/Ban action.

use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::info;

use crate::core::{DetectionEvent, DetectionType, Severity};
use crate::layer234::{
    ArpPacket, ArpStateTracker, DhcpPacket, DhcpStateTracker, Icmpv6Ra, RaStateTracker,
};

const ETHERTYPE_ARP: u16 = 0x0806;
const ETH_HDR_LEN: usize = 14;
const ICMPV6_TYPE_RA: u8 = 134;

/// Thresholds for the inline L2 trackers. Plain serialisable data so it can live
/// in `CaptureConfig` and be carried into the capture thread.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2InspectConfig {
    /// IP→MAC binding changes before an ARP spoof alert fires.
    pub arp_change_threshold: u32,
    /// Unique client MACs in the window before a DHCP-starvation alert fires.
    pub dhcp_starvation_threshold: u32,
    /// Distinct routers before an RA-flood alert fires.
    pub ra_flood_threshold: u32,
}

impl Default for L2InspectConfig {
    fn default() -> Self {
        // Same defaults as the standalone l2_monitor.
        Self {
            arp_change_threshold: 2,
            dhcp_starvation_threshold: 50,
            ra_flood_threshold: 10,
        }
    }
}

/// The L2 state trackers plus their config, owned by the capture.
///
/// Created once per capture and fed every raw frame. State (ARP bindings, DHCP
/// MAC sets, RA router sets) accumulates across frames so rate/rebind thresholds
/// can trip.
pub struct L2Inspector {
    arp: ArpStateTracker,
    dhcp: DhcpStateTracker,
    ra: RaStateTracker,
}

impl L2Inspector {
    /// Build an inspector with the given thresholds.
    pub fn new(cfg: &L2InspectConfig) -> Self {
        let mut arp = ArpStateTracker::new();
        arp.set_change_threshold(cfg.arp_change_threshold);
        let mut dhcp = DhcpStateTracker::new();
        dhcp.set_starvation_threshold(cfg.dhcp_starvation_threshold);
        let mut ra = RaStateTracker::new();
        ra.set_flood_threshold(cfg.ra_flood_threshold);
        Self { arp, dhcp, ra }
    }

    /// Inspect one raw Ethernet frame; return any L2/L3 attack detections.
    ///
    /// Cheap for the common case: a couple of byte reads to classify the frame,
    /// and only ARP/DHCP/RA frames touch a tracker. IP traffic that is not
    /// DHCP/RA returns immediately so the engine's normal pipeline owns it.
    pub fn inspect(&mut self, frame: &[u8]) -> Vec<DetectionEvent> {
        if frame.len() < ETH_HDR_LEN {
            return Vec::new();
        }

        // ARP is not IP, so etherparse's IP-oriented slicing won't carry it —
        // dispatch directly off the ethertype.
        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        if ethertype == ETHERTYPE_ARP {
            return self.inspect_arp(&frame[ETH_HDR_LEN..]);
        }

        // DHCP (IPv4/UDP 67/68) and RA (IPv6/ICMPv6 type 134) ride normal IP
        // framing.
        let sliced = match SlicedPacket::from_ethernet(frame) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        match (&sliced.net, &sliced.transport) {
            (Some(NetSlice::Ipv4(ipv4)), Some(TransportSlice::Udp(udp))) => {
                let (sp, dp) = (udp.source_port(), udp.destination_port());
                if sp == 67 || sp == 68 || dp == 67 || dp == 68 {
                    let src_ip = ipv4.header().source_addr();
                    return self.inspect_dhcp(udp.payload(), src_ip);
                }
                Vec::new()
            }
            (Some(NetSlice::Ipv6(ipv6)), Some(TransportSlice::Icmpv6(icmp6))) => {
                let bytes = icmp6.slice();
                if bytes.first().copied() == Some(ICMPV6_TYPE_RA) {
                    let src_ip = ipv6.header().source_addr();
                    return self.inspect_ra(bytes, src_ip);
                }
                Vec::new()
            }
            _ => Vec::new(),
        }
    }

    fn inspect_arp(&mut self, arp_bytes: &[u8]) -> Vec<DetectionEvent> {
        let Some(pkt) = ArpPacket::parse(arp_bytes) else {
            return Vec::new();
        };
        let Some(alert) = self.arp.process_arp(&pkt) else {
            return Vec::new();
        };
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
            Severity::High,
            reason,
        )]
    }

    fn inspect_dhcp(&mut self, payload: &[u8], src_ip: Ipv4Addr) -> Vec<DetectionEvent> {
        let Some(pkt) = DhcpPacket::parse(payload) else {
            return Vec::new();
        };
        let (starvation, rogue) = self.dhcp.process_dhcp(&pkt, src_ip);
        let mut out = Vec::new();
        if let Some(a) = starvation {
            let reason = format!(
                "DHCP starvation: {} unique MACs, {} requests in {}s",
                a.unique_macs, a.requests_in_window, a.window_seconds
            );
            out.push(attack(
                IpAddr::V4(src_ip),
                "l2_dhcp",
                "dhcp_starvation",
                Severity::High,
                reason,
            ));
        }
        if let Some(a) = rogue {
            let reason = format!("Rogue DHCP server {} ({} offers)", a.server_ip, a.offers_count);
            out.push(attack(
                IpAddr::V4(a.server_ip),
                "l2_dhcp",
                "rogue_dhcp",
                Severity::High,
                reason,
            ));
        }
        out
    }

    fn inspect_ra(&mut self, icmpv6: &[u8], src_ip: Ipv6Addr) -> Vec<DetectionEvent> {
        let Some(pkt) = Icmpv6Ra::parse(icmpv6) else {
            return Vec::new();
        };
        let (spoof, flood) = self.ra.process_ra(&pkt, src_ip);
        let mut out = Vec::new();
        if let Some(a) = spoof {
            let mac = a.src_mac.map(|m| fmt_mac(&m)).unwrap_or_else(|| "?".into());
            let reason = format!(
                "IPv6 RA spoofing from {} (mac {}, router_lifetime {})",
                a.src_ip, mac, a.router_lifetime
            );
            out.push(attack(
                IpAddr::V6(a.src_ip),
                "l2_ra",
                "ra_spoofing",
                Severity::High,
                reason,
            ));
        }
        if let Some(a) = flood {
            let reason = format!(
                "IPv6 RA flood: {} routers, {:.1} RA/s",
                a.unique_routers, a.ra_per_sec
            );
            out.push(attack(
                IpAddr::V6(src_ip),
                "l2_ra",
                "ra_flood",
                Severity::Medium,
                reason,
            ));
        }
        out
    }
}

/// Build an engine-native detection event for an L2 finding (alert, not auto-ban).
///
/// L2 attacks have no clean dst — they are broadcast / address-assertion — so we
/// set dst = src. `DetectionEvent::new` defaults `action` to `Alert`, which the
/// engine bridge records without escalating to a ban.
fn attack(
    src: IpAddr,
    detector: &str,
    kind: &str,
    severity: Severity,
    reason: String,
) -> DetectionEvent {
    info!("inline L2: {}", reason);
    DetectionEvent::new(
        DetectionType::Custom(kind.to_string()),
        severity,
        src,
        src,
        reason,
    )
    .with_detector(detector)
}

fn fmt_mac(m: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal Ethernet+ARP frame (request/reply) asserting `sender_ip`
    /// is at `sender_mac`. 14-byte Ethernet header + 28-byte ARP for IPv4.
    fn arp_frame(sender_mac: [u8; 6], sender_ip: [u8; 4]) -> Vec<u8> {
        let mut f = Vec::with_capacity(42);
        // Ethernet: dst broadcast, src = sender, ethertype ARP.
        f.extend_from_slice(&[0xff; 6]);
        f.extend_from_slice(&sender_mac);
        f.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        // ARP: HTYPE=1, PTYPE=0x0800, HLEN=6, PLEN=4, OPER=2 (reply).
        f.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02]);
        f.extend_from_slice(&sender_mac); // sender HW
        f.extend_from_slice(&sender_ip); // sender proto
        f.extend_from_slice(&[0x00; 6]); // target HW
        f.extend_from_slice(&[0x00; 4]); // target proto
        f
    }

    #[test]
    fn arp_rebind_trips_after_threshold() {
        let cfg = L2InspectConfig {
            arp_change_threshold: 2,
            ..Default::default()
        };
        let mut insp = L2Inspector::new(&cfg);
        let ip = [192, 168, 1, 50];

        // First binding: learn it, no alert.
        let evs = insp.inspect(&arp_frame([0xaa; 6], ip));
        assert!(evs.is_empty(), "first binding should not alert");

        // Rebind the same IP to different MACs until the change threshold trips.
        insp.inspect(&arp_frame([0xbb; 6], ip));
        let evs = insp.inspect(&arp_frame([0xcc; 6], ip));
        assert!(
            evs.iter().any(|e| matches!(
                &e.event_type,
                DetectionType::Custom(k) if k == "arp_spoofing"
            )),
            "repeated IP→MAC rebinds should raise an arp_spoofing alert"
        );
        // It is an alert, never an auto-ban.
        assert!(evs.iter().all(|e| matches!(
            e.action,
            crate::core::DetectionAction::Alert
        )));
    }

    #[test]
    fn non_l2_frame_is_ignored() {
        let mut insp = L2Inspector::new(&L2InspectConfig::default());
        // Too short / not a recognised L2 attack frame.
        assert!(insp.inspect(&[0u8; 8]).is_empty());
        assert!(insp.inspect(&[0u8; ETH_HDR_LEN]).is_empty());
    }
}
