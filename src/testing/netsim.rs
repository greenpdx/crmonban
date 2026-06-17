//! Closed-loop network simulator for path-level IPS testing.
//!
//! Unlike the [`synthetic`](super::synthetic) generators — which emit packets
//! blindly — this harness models **reactive endpoints**: a [`MockServer`] only
//! sends a SYN-ACK if it actually received a SYN, only sends a "pong" if it
//! received a "ping", and so on. Wire these endpoints up to a mock netfilter
//! dataplane (Phase B) that runs the crmonban pipeline inline, and a *dropped*
//! packet genuinely suppresses the response it would have triggered — which is
//! the whole point of testing an inline IPS rather than a passive IDS.
//!
//! Because a benign client runs a full TCP conversation over one connection —
//! handshake, request/response ping-pong, teardown, all on a fixed 5-tuple in
//! both directions — the flow tracker accumulates real bidirectional flows that
//! reach `Established` and feed the learn-normal baseline. This is exactly what
//! the port-spraying `benign` synthetic preset could not produce.
//!
//! # Phases
//!
//! - **A** — the endpoint state machines ([`Tcb`], [`MockServer`], [`MockClient`]).
//! - **B/C** — [`MockDataplane`] (mock netfilter: conntrack funnel + inline
//!   pipeline) and [`PathNetwork`], which routes the endpoints' packets and
//!   applies pipeline verdicts so a dropped packet genuinely suppresses the
//!   response it would have caused. The same harness serves both the **INPUT**
//!   and **FORWARD** paths — only the IP addressing differs.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;

use crate::core::{AlertAnalyzer, AlertAnalyzerConfig, FlowKey};
use crate::engine::{PipelineConfig, WorkerConfig, WorkerThread};
use crate::types::pipeline::BlockPolicy;
use crate::types::{IpProtocol, Packet, TcpFlags};

/// A monotonic packet-id source shared across endpoints so every packet in a
/// run has a unique id (the dataplane owns one of these in Phase B).
#[derive(Debug, Default)]
pub struct IdGen(u64);

impl IdGen {
    /// Start ids at `start`.
    pub fn starting_at(start: u64) -> Self {
        Self(start)
    }

    /// Next id.
    pub fn next(&mut self) -> u64 {
        let id = self.0;
        self.0 += 1;
        id
    }
}

// === TCP flag helpers ===========================================================

fn flags(syn: bool, ack: bool, fin: bool, rst: bool, psh: bool) -> TcpFlags {
    TcpFlags { syn, ack, fin, rst, psh, urg: false, ece: false, cwr: false }
}

fn f_syn() -> TcpFlags {
    flags(true, false, false, false, false)
}
fn f_syn_ack() -> TcpFlags {
    flags(true, true, false, false, false)
}
fn f_ack() -> TcpFlags {
    flags(false, true, false, false, false)
}
fn f_psh_ack() -> TcpFlags {
    flags(false, true, false, false, true)
}
fn f_fin_ack() -> TcpFlags {
    flags(false, true, true, false, false)
}
fn f_rst_ack() -> TcpFlags {
    flags(false, true, false, true, false)
}

/// How many sequence numbers a segment consumes: payload bytes, plus one each
/// for SYN and FIN (the TCP "phantom byte" rule). Needed so both sides agree on
/// seq/ack across the handshake and teardown.
fn seq_len(fl: &TcpFlags, payload_len: usize) -> u32 {
    payload_len as u32 + (fl.syn as u32) + (fl.fin as u32)
}

// === Connection control block ===================================================

/// State of one side of a TCP connection, from the local endpoint's view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnState {
    /// No connection.
    Closed,
    /// Client sent SYN, awaiting SYN-ACK.
    SynSent,
    /// Server received SYN and replied SYN-ACK, awaiting the client's ACK.
    SynReceived,
    /// Three-way handshake complete; data may flow.
    Established,
    /// Local side sent FIN, awaiting the peer's FIN.
    FinWait,
    /// Local side received the peer's FIN and replied FIN-ACK, awaiting final ACK.
    LastAck,
}

/// One endpoint's transmission-control block: tracks the 5-tuple (from the local
/// side), connection state, and the send/receive sequence numbers so every
/// emitted segment carries a correct seq and ack. This is the reactive core —
/// both [`MockClient`] and [`MockServer`] drive their conversations through it.
#[derive(Debug, Clone)]
pub struct Tcb {
    local_ip: IpAddr,
    local_port: u16,
    remote_ip: IpAddr,
    remote_port: u16,
    /// Connection state.
    pub state: ConnState,
    /// Next sequence number we will send.
    snd_nxt: u32,
    /// Next sequence number we expect from the peer (i.e. our ack field).
    rcv_nxt: u32,
}

impl Tcb {
    /// New TCB for `local -> remote`, beginning with our initial send sequence
    /// `iss`. `Closed` until the owner opens (client) or accepts (server).
    fn new(
        local_ip: IpAddr,
        local_port: u16,
        remote_ip: IpAddr,
        remote_port: u16,
        iss: u32,
    ) -> Self {
        Self {
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            state: ConnState::Closed,
            snd_nxt: iss,
            rcv_nxt: 0,
        }
    }

    /// Build a segment local -> remote with the current seq/ack, then advance
    /// our send sequence by what the segment consumes.
    fn send(&mut self, id: &mut IdGen, fl: TcpFlags, payload: &[u8]) -> Packet {
        let mut pkt = Packet::new(
            id.next(),
            self.local_ip,
            self.remote_ip,
            IpProtocol::Tcp,
            "netsim",
        );
        if let Some(tcp) = pkt.tcp_mut() {
            tcp.src_port = self.local_port;
            tcp.dst_port = self.remote_port;
            tcp.flags = fl.clone();
            tcp.seq = self.snd_nxt;
            tcp.ack = self.rcv_nxt;
            tcp.window = 64240;
            tcp.payload = payload.to_vec();
        }
        pkt.raw_len = 40 + payload.len() as u32;
        self.snd_nxt = self.snd_nxt.wrapping_add(seq_len(&fl, payload.len()));
        pkt
    }

    /// Update what we expect next from the peer, given a segment they sent us.
    /// Their SYN/FIN and payload bytes each advance our ack pointer.
    fn observe(&mut self, pkt: &Packet) {
        if let Some(tcp) = pkt.tcp() {
            // The next sequence we expect is the peer's seq plus what this
            // segment consumed (payload bytes, +1 each for their SYN and FIN).
            // This holds for the first segment (their SYN/SYN-ACK) and after.
            let consumed = seq_len(&tcp.flags, tcp.payload.len());
            self.rcv_nxt = tcp.seq.wrapping_add(consumed);
        }
    }
}

// === Mock server ================================================================

/// A reactive TCP server: listens on a set of ports, accepts connections, and
/// echoes an application-level "pong" for each "ping". A SYN to a closed port is
/// refused with RST (so port scans see realistic open/closed behavior).
pub struct MockServer {
    ip: IpAddr,
    open_ports: Vec<u16>,
    /// Active connections keyed by the client's (ip, port).
    conns: HashMap<(IpAddr, u16), Tcb>,
    /// Initial send sequence handed to the next accepted connection
    /// (deterministic, bumped per accept).
    next_iss: u32,
}

impl MockServer {
    /// New server at `ip` listening on `open_ports`.
    pub fn new(ip: IpAddr, open_ports: Vec<u16>) -> Self {
        Self { ip, open_ports, conns: HashMap::new(), next_iss: 0x5000_0000 }
    }

    /// This server's address.
    pub fn ip(&self) -> IpAddr {
        self.ip
    }

    /// Is `port` accepting connections?
    pub fn listens_on(&self, port: u16) -> bool {
        self.open_ports.contains(&port)
    }

    /// Application response for a received request. A real HTTP-ish reply on 80,
    /// a generic ack-body elsewhere — enough to give flows a realistic shape.
    fn response_for(port: u16, _request: &[u8]) -> Vec<u8> {
        match port {
            80 | 8080 => b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npong".to_vec(),
            443 => b"\x17\x03\x03\x00\x04pong".to_vec(),
            _ => b"+OK pong\r\n".to_vec(),
        }
    }

    /// Feed the server a packet destined for it; returns the packets it sends in
    /// response (possibly none). Only TCP to this server's IP is handled.
    pub fn deliver(&mut self, pkt: &Packet, id: &mut IdGen) -> Vec<Packet> {
        if pkt.dst_ip() != self.ip || pkt.protocol() != IpProtocol::Tcp {
            return Vec::new();
        }
        let tcp = match pkt.tcp() {
            Some(t) => t,
            None => return Vec::new(),
        };
        let client = (pkt.src_ip(), tcp.src_port);
        let dst_port = tcp.dst_port;
        let fl = &tcp.flags;
        let mut out = Vec::new();

        // A SYN to a closed port: refuse with RST regardless of any state.
        if fl.is_syn_only() && !self.listens_on(dst_port) {
            let iss = self.next_iss;
            let mut tcb = Tcb::new(self.ip, dst_port, client.0, client.1, iss);
            tcb.observe(pkt);
            out.push(tcb.send(id, f_rst_ack(), &[]));
            return out;
        }

        // SYN to an open port: accept, reply SYN-ACK.
        if fl.is_syn_only() {
            let iss = self.next_iss;
            self.next_iss = self.next_iss.wrapping_add(0x1_0000);
            let mut tcb = Tcb::new(self.ip, dst_port, client.0, client.1, iss);
            tcb.observe(pkt);
            tcb.state = ConnState::SynReceived;
            out.push(tcb.send(id, f_syn_ack(), &[]));
            self.conns.insert(client, tcb);
            return out;
        }

        let tcb = match self.conns.get_mut(&client) {
            Some(t) => t,
            None => return out, // stray segment for an unknown connection
        };

        if fl.rst {
            self.conns.remove(&client);
            return out;
        }

        match tcb.state {
            // The ACK that completes the handshake. A real client piggybacks its
            // first request onto this segment, so it may also carry data — if so,
            // answer it right away (the same path the established arm takes).
            ConnState::SynReceived if fl.ack => {
                tcb.observe(pkt);
                tcb.state = ConnState::Established;
                if !tcp.payload.is_empty() {
                    let body = Self::response_for(dst_port, &tcp.payload);
                    out.push(tcb.send(id, f_psh_ack(), &body));
                }
            }
            // A request "ping" — observe it and answer with a "pong" (the
            // response segment also acks the request).
            ConnState::Established if !tcp.payload.is_empty() => {
                tcb.observe(pkt);
                let body = Self::response_for(dst_port, &tcp.payload);
                out.push(tcb.send(id, f_psh_ack(), &body));
            }
            // Client is closing: ack nothing extra, reply with our FIN.
            ConnState::Established if fl.fin => {
                tcb.observe(pkt);
                out.push(tcb.send(id, f_fin_ack(), &[]));
                tcb.state = ConnState::LastAck;
            }
            // Client's final ACK of our FIN.
            ConnState::LastAck if fl.ack => {
                tcb.observe(pkt);
                tcb.state = ConnState::Closed;
                self.conns.remove(&client);
            }
            _ => {}
        }
        out
    }

    /// Number of connections currently tracked (for assertions/stats).
    pub fn active_conns(&self) -> usize {
        self.conns.len()
    }
}

// === Mock client ================================================================

/// A reactive TCP client that opens one connection to a server, sends a fixed
/// number of request "pings", consumes the "pongs", and closes cleanly. Driving
/// it through the dataplane yields a complete, realistic bidirectional flow.
pub struct MockClient {
    tcb: Tcb,
    /// Remaining request/response rounds to perform before closing.
    rounds_left: u32,
    /// Request payload sent each round.
    request: Vec<u8>,
    /// Set once we have closed, so the driver knows the conversation is done.
    finished: bool,
}

impl MockClient {
    /// New client `src -> (dst_ip, dst_port)` that will perform `rounds`
    /// request/response exchanges. `iss` is its initial sequence number.
    pub fn new(
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        rounds: u32,
        iss: u32,
    ) -> Self {
        Self {
            tcb: Tcb::new(src_ip, src_port, dst_ip, dst_port, iss),
            rounds_left: rounds.max(1),
            request: b"GET / HTTP/1.1\r\nHost: sim\r\n\r\nping".to_vec(),
            finished: false,
        }
    }

    /// Has the connection fully closed?
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// Current connection state (for assertions/stats).
    pub fn state(&self) -> ConnState {
        self.tcb.state
    }

    /// Begin the active open: returns the initial SYN.
    pub fn open(&mut self, id: &mut IdGen) -> Vec<Packet> {
        debug_assert_eq!(self.tcb.state, ConnState::Closed);
        let syn = self.tcb.send(id, f_syn(), &[]);
        self.tcb.state = ConnState::SynSent;
        vec![syn]
    }

    /// Feed the client a packet from the server; returns its response packets.
    pub fn deliver(&mut self, pkt: &Packet, id: &mut IdGen) -> Vec<Packet> {
        if pkt.protocol() != IpProtocol::Tcp {
            return Vec::new();
        }
        let tcp = match pkt.tcp() {
            Some(t) => t,
            None => return Vec::new(),
        };
        let fl = &tcp.flags;
        let mut out = Vec::new();

        if fl.rst {
            self.finished = true;
            self.tcb.state = ConnState::Closed;
            return out;
        }

        match self.tcb.state {
            // Handshake completes: ACK it and immediately send the first request
            // (the ACK is piggybacked on the data segment, as a real client does).
            ConnState::SynSent if fl.is_syn_ack() => {
                self.tcb.observe(pkt);
                self.tcb.state = ConnState::Established;
                out.push(self.tcb.send(id, f_psh_ack(), &self.request));
                self.rounds_left -= 1;
            }
            // A "pong": either fire the next request or begin teardown.
            ConnState::Established if !tcp.payload.is_empty() => {
                self.tcb.observe(pkt);
                if self.rounds_left > 0 {
                    out.push(self.tcb.send(id, f_psh_ack(), &self.request));
                    self.rounds_left -= 1;
                } else {
                    out.push(self.tcb.send(id, f_fin_ack(), &[]));
                    self.tcb.state = ConnState::FinWait;
                }
            }
            // Server's FIN: send the final ACK and we're done.
            ConnState::FinWait if fl.fin => {
                self.tcb.observe(pkt);
                out.push(self.tcb.send(id, f_ack(), &[]));
                self.tcb.state = ConnState::Closed;
                self.finished = true;
            }
            _ => {}
        }
        out
    }
}

// === Mock netfilter: conntrack funnel ==========================================

/// Default first-N: how many original-direction packets of an undecided flow are
/// handed to the pipeline before the flow is bypassed in-kernel. Mirrors the
/// `ct packets dir original <= N` match in `firewall.rs add_dpi_chain`.
pub const DEFAULT_FIRST_N: u64 = 8;

/// One flow's conntrack state in the mock dataplane.
struct CtEntry {
    /// Source of the flow's *original* direction (the side that sent the SYN).
    orig_ip: IpAddr,
    orig_port: u16,
    /// Packets seen so far in the original direction.
    orig_packets: u64,
    /// ct-mark "good": the pipeline marked this flow for in-kernel bypass.
    good: bool,
}

/// What the mock netfilter decides for a packet reaching the dpi chain — the
/// funnel from `firewall.rs add_dpi_chain`: whitelisted and ct-mark-good flows
/// are accepted untouched; the first N original-direction packets of an
/// undecided flow are inspected; everything past that is bypassed in-kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CtDecision {
    /// Source is whitelisted — accept, never inspect.
    Whitelisted,
    /// Flow already decided, or served its first-N — accept without inspection.
    Bypass,
    /// Hand to the pipeline.
    Inspect,
}

/// Minimal connection tracker reproducing the kernel-side funnel: a whitelist,
/// a per-flow ct-mark-good bypass, and the first-N opening-packet rule. This is
/// what makes the simulation measure how much traffic actually reaches userspace.
struct Conntrack {
    flows: HashMap<FlowKey, CtEntry>,
    whitelist: HashSet<IpAddr>,
    first_n: u64,
}

impl Conntrack {
    fn new(first_n: u64) -> Self {
        Self { flows: HashMap::new(), whitelist: HashSet::new(), first_n }
    }

    fn decide(&mut self, pkt: &Packet) -> CtDecision {
        if self.whitelist.contains(&pkt.src_ip()) {
            return CtDecision::Whitelisted;
        }
        let key = FlowKey::from_packet(pkt);

        // A fresh SYN is a new connection on this 5-tuple: reset the entry so it
        // is inspected anew instead of inheriting a stale verdict (mirrors the
        // SYN-invalidation in the real flow cache).
        let is_syn = pkt
            .tcp()
            .map(|t| t.flags.syn && !t.flags.ack)
            .unwrap_or(false);
        if is_syn {
            self.flows.insert(
                key.clone(),
                CtEntry { orig_ip: pkt.src_ip(), orig_port: pkt.src_port(), orig_packets: 0, good: false },
            );
        }

        let entry = self.flows.entry(key).or_insert_with(|| CtEntry {
            orig_ip: pkt.src_ip(),
            orig_port: pkt.src_port(),
            orig_packets: 0,
            good: false,
        });

        if entry.good {
            return CtDecision::Bypass;
        }
        let is_original = pkt.src_ip() == entry.orig_ip && pkt.src_port() == entry.orig_port;
        if is_original {
            entry.orig_packets += 1;
        }
        if entry.orig_packets <= self.first_n {
            CtDecision::Inspect
        } else {
            CtDecision::Bypass
        }
    }

    fn mark_good(&mut self, pkt: &Packet) {
        if let Some(e) = self.flows.get_mut(&FlowKey::from_packet(pkt)) {
            e.good = true;
        }
    }
}

// === Mock dataplane ============================================================

/// The decision the mock netfilter reached for one packet.
#[derive(Debug, Clone)]
pub enum Admission {
    /// Delivered to its destination. `inspected` = the pipeline ran (vs bypassed
    /// by whitelist/ct-good/first-N); `marked_good` = the pipeline marked the flow
    /// for the in-kernel fast-path.
    Accept { inspected: bool, marked_good: bool },
    /// Dropped by the pipeline verdict — no delivery, no response. `banned` is the
    /// source the engine would ban now that the verdict is enforced.
    Drop { banned: Option<IpAddr> },
}

/// A mock netfilter dataplane: the conntrack funnel in front of an inline
/// crmonban pipeline ([`WorkerThread`]). `admit` is the single decision point a
/// packet passes through on an inspected path.
pub struct MockDataplane {
    host_ip: IpAddr,
    worker: WorkerThread,
    config: PipelineConfig,
    ct: Conntrack,
}

impl MockDataplane {
    /// New dataplane protecting `host_ip`, inspecting the first `first_n`
    /// opening packets of each flow.
    pub fn new(host_ip: IpAddr, first_n: u64) -> Self {
        let mut worker = WorkerThread::new(WorkerConfig::default());
        worker.set_alert_analyzer(AlertAnalyzer::new(Self::strict_policy()));
        Self { host_ip, worker, config: PipelineConfig::default(), ct: Conntrack::new(first_n) }
    }

    /// The protected host's address.
    pub fn host_ip(&self) -> IpAddr {
        self.host_ip
    }

    /// Mutable pipeline worker (e.g. to block an IP or load rules in a test).
    pub fn worker_mut(&mut self) -> &mut WorkerThread {
        &mut self.worker
    }

    /// Mutable pipeline config (e.g. to enable a stage or turn on tracing).
    pub fn config_mut(&mut self) -> &mut PipelineConfig {
        &mut self.config
    }

    /// Add a source IP to the conntrack whitelist (accepted without inspection).
    pub fn whitelist(&mut self, ip: IpAddr) {
        self.ct.whitelist.insert(ip);
    }

    /// Has the learn-normal model trained on `min` clean flows yet?
    pub fn model_ready(&self, min: u64) -> bool {
        self.worker.normal_model().read().is_ready(min)
    }

    /// Strict IPS posture for path testing: block High and Critical immediately,
    /// so a single malicious packet is dropped. The default blocks High only
    /// after a threshold, which would obscure the closed-loop feedback under test.
    fn strict_policy() -> AlertAnalyzerConfig {
        let mut cfg = AlertAnalyzerConfig::default();
        cfg.severity_policy.high = BlockPolicy::BlockImmediately;
        cfg.severity_policy.critical = BlockPolicy::BlockImmediately;
        cfg
    }

    /// Run a packet through the mock netfilter: the conntrack funnel, then the
    /// pipeline if the funnel says to inspect. Returns the admission decision.
    pub async fn admit(&mut self, pkt: &Packet) -> Admission {
        match self.ct.decide(pkt) {
            CtDecision::Whitelisted | CtDecision::Bypass => {
                Admission::Accept { inspected: false, marked_good: false }
            }
            CtDecision::Inspect => {
                let analysis = self.worker.process_full(pkt.clone(), &self.config).await;
                if analysis.verdict.is_blocking() {
                    Admission::Drop { banned: Some(pkt.src_ip()) }
                } else {
                    let marked_good = analysis.fast_path_good;
                    if marked_good {
                        self.ct.mark_good(pkt);
                    }
                    Admission::Accept { inspected: true, marked_good }
                }
            }
        }
    }
}

// === INPUT-path network orchestrator ===========================================

/// Tallies of what the simulation did — the payoff numbers: how much traffic was
/// inspected vs bypassed (the funnel), and how many packets were dropped/banned.
#[derive(Debug, Default, Clone)]
pub struct NetSimStats {
    /// Packets entering an inspected path — terminating at the host (INPUT) or
    /// transiting it (FORWARD). Equals `input + forward`.
    pub inbound: u64,
    /// Packets routed to INPUT: destination IP is the host's own address.
    pub input: u64,
    /// Packets routed to FORWARD: destination IP is elsewhere (transit).
    pub forward: u64,
    /// Host-originated packets (OUTPUT path — trusted, not inspected). Nonzero
    /// only on the INPUT path, where the host itself is the server.
    pub outbound: u64,
    /// Inbound packets that ran the pipeline.
    pub inspected: u64,
    /// Inbound packets accepted without inspection (whitelist / ct-good / past first-N).
    pub bypassed: u64,
    /// Inbound packets accepted (delivered to the host).
    pub accepted: u64,
    /// Inbound packets dropped by a blocking verdict.
    pub dropped: u64,
    /// Sources the engine would ban (one per dropped, decided flow).
    pub bans: u64,
    /// True if the run hit its step budget before going quiescent.
    pub aborted: bool,
}

/// Which netfilter path a packet takes, decided as the kernel routes it. A
/// host-originated packet takes OUTPUT; otherwise the **destination IP** selects
/// the path — destined to the host's own address it is delivered locally
/// (INPUT), destined elsewhere it is routed through (FORWARD).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Path {
    /// Source is the host — a locally generated packet (e.g. a local server's
    /// reply). Trusted; not inspected.
    Output,
    /// Destination is the host's own address — delivered locally, inspected at
    /// the input hook.
    Input,
    /// Destination is elsewhere — routed through the host, inspected at the
    /// forward hook.
    Forward,
}

/// A closed-loop path simulation. The same client/server endpoints model **both**
/// netfilter paths — the only difference is the addressing:
///
/// - **INPUT**: the server runs *on* the protected host (`server.ip() == host`).
///   Requests terminate at the host and are inspected; the host's replies leave
///   via OUTPUT and are trusted (not inspected).
/// - **FORWARD**: the host is a *router* at a distinct `host_ip`, and the server
///   lives behind it at a different address. Neither endpoint is the host, so
///   **both directions** transit the forward hook and are inspected.
///
/// Routing falls straight out of one question per packet — *did the host
/// originate it?* If so it is trusted (OUTPUT); otherwise it terminates at the
/// host (INPUT) or transits it (FORWARD) and goes through the dpi chain. So the
/// run loop is path-agnostic; INPUT vs FORWARD is decided entirely by which IPs
/// you hand the constructor.
pub struct PathNetwork {
    dataplane: MockDataplane,
    server: MockServer,
    clients: HashMap<(IpAddr, u16), MockClient>,
    queue: VecDeque<Packet>,
    id: IdGen,
    stats: NetSimStats,
}

impl PathNetwork {
    fn with_host(host_ip: IpAddr, server: MockServer, first_n: u64) -> Self {
        Self {
            dataplane: MockDataplane::new(host_ip, first_n),
            server,
            clients: HashMap::new(),
            queue: VecDeque::new(),
            id: IdGen::default(),
            stats: NetSimStats::default(),
        }
    }

    /// **INPUT path**: the protected host runs `server` (the server's address is
    /// the host's). `first_n` sets how many opening packets of each flow are
    /// inspected. Requests are inspected; the host's replies are trusted.
    pub fn new_input(server: MockServer, first_n: u64) -> Self {
        let host_ip = server.ip();
        Self::with_host(host_ip, server, first_n)
    }

    /// **FORWARD path**: the protected host is a router at `host_ip`; `server`
    /// sits behind it at a *different* address. Both directions transit and are
    /// inspected. Same harness as [`new_input`](Self::new_input) — only the IPs
    /// differ.
    pub fn new_forward(host_ip: IpAddr, server: MockServer, first_n: u64) -> Self {
        debug_assert_ne!(host_ip, server.ip(), "forward server must not be the router/host");
        Self::with_host(host_ip, server, first_n)
    }

    /// Mutable access to the dataplane (block an IP, whitelist, tweak config).
    pub fn dataplane_mut(&mut self) -> &mut MockDataplane {
        &mut self.dataplane
    }

    /// Register a reactive client and enqueue its opening SYN.
    pub fn add_client(&mut self, mut client: MockClient) {
        let syns = client.open(&mut self.id);
        if let Some(syn) = syns.first() {
            let key = (syn.src_ip(), syn.tcp().map(|t| t.src_port).unwrap_or(0));
            self.clients.insert(key, client);
            self.queue.extend(syns);
        }
    }

    /// Inject a raw inbound packet toward the host (e.g. an attacker's SYN with
    /// no reactive client behind it — a flood or scan probe).
    pub fn inject_inbound(&mut self, pkt: Packet) {
        self.queue.push_back(pkt);
    }

    /// Classify a packet's netfilter path exactly as the kernel routes it: a
    /// host-originated packet takes OUTPUT; otherwise the **destination IP**
    /// decides — destined to the host's own address it is delivered locally
    /// (INPUT), destined elsewhere it is routed through (FORWARD).
    fn classify(&self, pkt: &Packet) -> Path {
        let host = self.dataplane.host_ip();
        if pkt.src_ip() == host {
            Path::Output
        } else if pkt.dst_ip() == host {
            Path::Input
        } else {
            Path::Forward
        }
    }

    /// Hand a packet to whichever endpoint owns its destination (the server, or
    /// a registered client) and collect that endpoint's responses. Path-agnostic:
    /// the server is matched by IP, a client by (ip, port).
    fn deliver_to_endpoint(&mut self, pkt: &Packet) -> Vec<Packet> {
        if pkt.dst_ip() == self.server.ip() {
            self.server.deliver(pkt, &mut self.id)
        } else if let Some(client) = self.clients.get_mut(&(pkt.dst_ip(), pkt.dst_port())) {
            client.deliver(pkt, &mut self.id)
        } else {
            Vec::new()
        }
    }

    /// Run the simulation to quiescence, or until `max_steps` packets have been
    /// routed (a runaway guard). Returns the accumulated stats.
    pub async fn run(&mut self, max_steps: usize) -> NetSimStats {
        let mut steps = 0usize;
        while let Some(pkt) = self.queue.pop_front() {
            steps += 1;
            if steps > max_steps {
                self.stats.aborted = true;
                break;
            }

            // The destination IP routes the packet: OUTPUT (host-originated,
            // trusted), INPUT (destined to the host), or FORWARD (transit). INPUT
            // and FORWARD both go through the dpi chain; OUTPUT is trusted.
            match self.classify(&pkt) {
                Path::Output => {
                    self.stats.outbound += 1;
                    let replies = self.deliver_to_endpoint(&pkt);
                    self.queue.extend(replies);
                    continue;
                }
                Path::Input => self.stats.input += 1,
                Path::Forward => self.stats.forward += 1,
            }

            self.stats.inbound += 1;
            match self.dataplane.admit(&pkt).await {
                Admission::Accept { inspected, marked_good: _ } => {
                    self.stats.accepted += 1;
                    if inspected {
                        self.stats.inspected += 1;
                    } else {
                        self.stats.bypassed += 1;
                    }
                    let replies = self.deliver_to_endpoint(&pkt);
                    self.queue.extend(replies);
                }
                Admission::Drop { banned } => {
                    self.stats.inspected += 1; // a drop is always an inspected packet
                    self.stats.dropped += 1;
                    if banned.is_some() {
                        self.stats.bans += 1;
                    }
                    // No delivery, no reply: the closed loop in action.
                }
            }
        }
        self.stats.clone()
    }

    /// The accumulated stats.
    pub fn stats(&self) -> &NetSimStats {
        &self.stats
    }

    /// Look up a registered client by its (ip, port) — for post-run assertions.
    pub fn client(&self, ip: IpAddr, port: u16) -> Option<&MockClient> {
        self.clients.get(&(ip, port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    /// Shuttle packets between a client and server with NO drops, until the
    /// client closes. Returns every packet that crossed the wire, in order.
    fn run_conversation(client: &mut MockClient, server: &mut MockServer, id: &mut IdGen) -> Vec<Packet> {
        let mut wire = Vec::new();
        // In-flight packets waiting to be delivered to their destination.
        let mut pending = client.open(id);
        let mut guard = 0;
        while !pending.is_empty() {
            guard += 1;
            assert!(guard < 1000, "conversation did not converge");
            let mut next = Vec::new();
            for pkt in pending.drain(..) {
                let to_server = pkt.dst_ip() == server.ip();
                let replies = if to_server {
                    server.deliver(&pkt, id)
                } else {
                    client.deliver(&pkt, id)
                };
                wire.push(pkt);
                next.extend(replies);
            }
            pending = next;
        }
        wire
    }

    #[test]
    fn pingpong_completes_and_builds_a_bidirectional_flow() {
        let client_ip = ip(203, 0, 113, 7);
        let server_ip = ip(10, 0, 0, 1);
        let mut client = MockClient::new(client_ip, 40001, server_ip, 80, 3, 0x1000_0000);
        let mut server = MockServer::new(server_ip, vec![80, 443]);
        let mut id = IdGen::default();

        let wire = run_conversation(&mut client, &mut server, &mut id);

        assert!(client.is_finished(), "client should close cleanly");
        assert_eq!(client.state(), ConnState::Closed);
        assert_eq!(server.active_conns(), 0, "server should release the connection");

        // A 3-round conversation is well over the learn-normal threshold (8).
        assert!(wire.len() >= 8, "flow too short: {} packets", wire.len());

        // Both directions must be present (this is what the port-spraying
        // synthetic benign preset failed to produce).
        let fwd = wire.iter().filter(|p| p.dst_ip() == server_ip).count();
        let bwd = wire.iter().filter(|p| p.src_ip() == server_ip).count();
        assert!(fwd > 0 && bwd > 0, "expected both directions: fwd={fwd} bwd={bwd}");

        // First packet is the SYN, and a SYN-ACK must come back.
        assert!(wire[0].tcp().unwrap().flags.is_syn_only());
        assert!(wire.iter().any(|p| p.tcp().unwrap().flags.is_syn_ack()));
        // A clean teardown: at least one FIN in each direction.
        assert!(wire.iter().any(|p| p.dst_ip() == server_ip && p.tcp().unwrap().flags.fin));
        assert!(wire.iter().any(|p| p.src_ip() == server_ip && p.tcp().unwrap().flags.fin));
    }

    #[test]
    fn syn_to_closed_port_is_refused_with_rst() {
        let client_ip = ip(203, 0, 113, 9);
        let server_ip = ip(10, 0, 0, 1);
        let mut server = MockServer::new(server_ip, vec![80]);
        let mut id = IdGen::default();

        // Hand-craft a SYN to a closed port (port 9999).
        let mut client = MockClient::new(client_ip, 40002, server_ip, 9999, 1, 0x2000_0000);
        let syn = client.open(&mut id);
        let replies = server.deliver(&syn[0], &mut id);

        assert_eq!(replies.len(), 1, "closed port should answer once");
        let rst = replies[0].tcp().unwrap();
        assert!(rst.flags.rst, "closed port must reply RST");
        assert_eq!(server.active_conns(), 0, "no connection should be tracked");
    }

    #[test]
    fn seq_and_ack_track_across_the_handshake() {
        let client_ip = ip(203, 0, 113, 11);
        let server_ip = ip(10, 0, 0, 1);
        let mut client = MockClient::new(client_ip, 40003, server_ip, 80, 1, 0x3000_0000);
        let mut server = MockServer::new(server_ip, vec![80]);
        let mut id = IdGen::default();

        let syn = client.open(&mut id);
        let syn_seq = syn[0].tcp().unwrap().seq;

        let synack = server.deliver(&syn[0], &mut id);
        let sa = synack[0].tcp().unwrap();
        // Server must ack our SYN's sequence + 1 (the SYN phantom byte).
        assert_eq!(sa.ack, syn_seq.wrapping_add(1));

        // Client's first data segment must ack the server's ISS + 1.
        let req = client.deliver(&synack[0], &mut id);
        let r = req[0].tcp().unwrap();
        assert_eq!(r.ack, sa.seq.wrapping_add(1));
    }

    // === Phase B: dataplane + INPUT path =======================================

    #[tokio::test]
    async fn benign_input_flow_is_admitted_and_served() {
        let server = MockServer::new(ip(10, 0, 0, 1), vec![80, 443]);
        let mut net = PathNetwork::new_input(server, DEFAULT_FIRST_N);
        let client_ip = ip(203, 0, 113, 20);
        net.add_client(MockClient::new(client_ip, 50001, ip(10, 0, 0, 1), 80, 4, 0x1000_0000));

        let stats = net.run(10_000).await;

        // The conversation completed end to end through the dataplane.
        assert!(net.client(client_ip, 50001).unwrap().is_finished());
        assert_eq!(stats.dropped, 0, "benign flow must not be dropped");
        assert!(stats.inbound > 0 && stats.outbound > 0, "traffic must flow both ways");
        // Server is on the host, so every inspected packet routes to INPUT and
        // the host's replies take OUTPUT — nothing is forwarded.
        assert!(stats.input > 0 && stats.forward == 0, "host-local traffic is INPUT, not FORWARD");
        // The server actually answered (pongs went back out).
        assert!(stats.accepted >= stats.inbound, "all inbound benign packets accepted");
    }

    #[tokio::test]
    async fn blocked_source_syn_is_dropped_and_gets_no_reply() {
        let server = MockServer::new(ip(10, 0, 0, 1), vec![80]);
        let mut net = PathNetwork::new_input(server, DEFAULT_FIRST_N);

        // Mark an attacker IP as known-bad in the pipeline's IP filter.
        let attacker = ip(198, 51, 100, 66);
        net.dataplane_mut()
            .worker_mut()
            .block_ip(attacker, "known bad (test)".to_string());

        // The attacker opens a connection; its SYN must be dropped inline, so the
        // server never sees it and no SYN-ACK is produced — the closed loop.
        let mut atk = MockClient::new(attacker, 40000, ip(10, 0, 0, 1), 80, 3, 0x2000_0000);
        let mut id = IdGen::starting_at(900_000);
        for syn in atk.open(&mut id) {
            net.inject_inbound(syn);
        }

        let stats = net.run(10_000).await;

        assert!(stats.dropped >= 1, "blocked source SYN must be dropped");
        assert!(stats.bans >= 1, "a drop on a decided flow bans the source");
        assert_eq!(stats.outbound, 0, "dropped SYN must produce no host reply");
        assert!(!atk.is_finished(), "attacker connection cannot establish");
    }

    #[tokio::test]
    async fn first_n_funnel_caps_inspection_then_bypasses() {
        let server = MockServer::new(ip(10, 0, 0, 1), vec![80]);
        // Inspect only the first 2 opening packets; the rest of the flow bypasses.
        let first_n = 2;
        let mut net = PathNetwork::new_input(server, first_n);
        let client_ip = ip(203, 0, 113, 30);
        // 5 rounds => well more than `first_n` inbound packets on the flow.
        net.add_client(MockClient::new(client_ip, 50002, ip(10, 0, 0, 1), 80, 5, 0x3000_0000));

        let stats = net.run(10_000).await;

        assert!(net.client(client_ip, 50002).unwrap().is_finished());
        assert!(stats.inspected <= first_n, "funnel must cap inspection at first-N: {}", stats.inspected);
        assert!(stats.bypassed >= 1, "packets past first-N must bypass the pipeline");
        assert_eq!(stats.dropped, 0);
    }

    #[tokio::test]
    async fn whitelisted_source_is_never_inspected() {
        let server = MockServer::new(ip(10, 0, 0, 1), vec![80]);
        let mut net = PathNetwork::new_input(server, DEFAULT_FIRST_N);
        let client_ip = ip(203, 0, 113, 40);
        net.dataplane_mut().whitelist(client_ip);
        net.add_client(MockClient::new(client_ip, 50003, ip(10, 0, 0, 1), 80, 3, 0x4000_0000));

        let stats = net.run(10_000).await;

        assert!(net.client(client_ip, 50003).unwrap().is_finished());
        assert_eq!(stats.inspected, 0, "whitelisted source must skip the pipeline entirely");
        assert!(stats.bypassed > 0);
    }

    // === Phase C: FORWARD path (same endpoints, different IPs) ==================

    #[tokio::test]
    async fn forward_benign_flow_inspects_both_directions() {
        // Host is a router; the server lives behind it at a distinct address, so
        // neither endpoint is the host and ALL traffic transits the dpi chain.
        let router = ip(192, 168, 0, 1);
        let server_ip = ip(93, 184, 216, 34);
        let server = MockServer::new(server_ip, vec![80]);
        let mut net = PathNetwork::new_forward(router, server, DEFAULT_FIRST_N);

        let client_ip = ip(192, 168, 0, 50);
        net.add_client(MockClient::new(client_ip, 51000, server_ip, 80, 4, 0x1000_0000));

        let stats = net.run(10_000).await;

        assert!(net.client(client_ip, 51000).unwrap().is_finished());
        assert_eq!(stats.dropped, 0, "benign forward flow must not be dropped");
        // The defining FORWARD property: the router originates nothing, so there
        // is no trusted OUTPUT traffic — the server's replies are inspected
        // transit, unlike INPUT where they would be trusted.
        assert_eq!(stats.outbound, 0, "router originates nothing; both directions transit");
        // The destination is never the host, so every packet routes to FORWARD.
        assert!(stats.forward > 0 && stats.input == 0, "transit traffic is FORWARD, not INPUT");
        assert!(stats.inbound > 0 && stats.inspected > 0);
    }

    #[tokio::test]
    async fn forward_blocked_source_syn_is_dropped() {
        let router = ip(192, 168, 0, 1);
        let server_ip = ip(93, 184, 216, 34);
        let server = MockServer::new(server_ip, vec![80]);
        let mut net = PathNetwork::new_forward(router, server, DEFAULT_FIRST_N);

        // A compromised LAN host (known-bad) trying to reach the WAN server.
        let attacker = ip(192, 168, 0, 66);
        net.dataplane_mut()
            .worker_mut()
            .block_ip(attacker, "compromised lan host (test)".to_string());

        let mut atk = MockClient::new(attacker, 40000, server_ip, 80, 2, 0x2000_0000);
        let mut id = IdGen::starting_at(700_000);
        for syn in atk.open(&mut id) {
            net.inject_inbound(syn);
        }

        let stats = net.run(10_000).await;

        assert!(stats.dropped >= 1, "blocked LAN host SYN must be dropped on the forward path");
        assert!(stats.bans >= 1);
        assert_eq!(stats.outbound, 0);
        assert!(!atk.is_finished(), "forwarded connection cannot establish");
    }
}
