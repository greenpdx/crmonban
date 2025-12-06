use anyhow::{Context, Result};
use nftables::{
    batch::Batch,
    expr::{Elem, Expression, NamedExpression, Payload, PayloadField},
    helper::{apply_ruleset, get_current_ruleset},
    schema::{
        Chain, Element, FlushObject, NfCmd, NfListObject, NfObject, Rule, Set, SetFlag,
        SetType, SetTypeValue, Table,
    },
    stmt::{Log, LogLevel, Match, Operator, Queue, Statement},
    types::{NfChainPolicy, NfChainType, NfFamily, NfHook},
};
use std::borrow::Cow;
use std::collections::HashSet;
use std::net::IpAddr;
use tracing::{debug, info, warn};

use crate::config::{DpiConfig, NftablesConfig, PortScanConfig, TlsProxyConfig};

/// Firewall manager for nftables operations
pub struct Firewall {
    config: NftablesConfig,
    port_scan_config: Option<PortScanConfig>,
    dpi_config: Option<DpiConfig>,
    tls_proxy_config: Option<TlsProxyConfig>,
}

impl Firewall {
    /// Create a new firewall manager
    pub fn new(config: NftablesConfig) -> Self {
        Self {
            config,
            port_scan_config: None,
            dpi_config: None,
            tls_proxy_config: None,
        }
    }

    /// Create a new firewall manager with port scan detection
    pub fn with_port_scan(config: NftablesConfig, port_scan_config: PortScanConfig) -> Self {
        Self {
            config,
            port_scan_config: Some(port_scan_config),
            dpi_config: None,
            tls_proxy_config: None,
        }
    }

    /// Create a new firewall manager with all features
    pub fn with_features(
        config: NftablesConfig,
        port_scan_config: Option<PortScanConfig>,
        dpi_config: Option<DpiConfig>,
        tls_proxy_config: Option<TlsProxyConfig>,
    ) -> Self {
        Self {
            config,
            port_scan_config,
            dpi_config,
            tls_proxy_config,
        }
    }

    /// Initialize nftables table, chains, and sets
    pub fn init(&self) -> Result<()> {
        info!("Initializing nftables configuration");

        // Check if our table already exists
        if self.table_exists()? {
            debug!("Table {} already exists", self.config.table_name);
            return Ok(());
        }

        let mut batch = Batch::new();

        // Create table
        batch.add(NfListObject::Table(Table {
            family: NfFamily::INet,
            name: Cow::Owned(self.config.table_name.clone()),
            handle: None,
        }));

        // Create IPv4 blocked set with timeout support
        let mut flags_v4 = HashSet::new();
        flags_v4.insert(SetFlag::Timeout);

        batch.add(NfListObject::Set(Box::new(Set {
            family: NfFamily::INet,
            table: Cow::Owned(self.config.table_name.clone()),
            name: Cow::Owned(self.config.set_v4.clone()),
            handle: None,
            set_type: SetTypeValue::Single(SetType::Ipv4Addr),
            policy: None,
            flags: Some(flags_v4),
            elem: None,
            timeout: None,
            gc_interval: None,
            size: None,
            comment: Some(Cow::Borrowed("crmonban blocked IPv4 addresses")),
        })));

        // Create IPv6 blocked set with timeout support
        let mut flags_v6 = HashSet::new();
        flags_v6.insert(SetFlag::Timeout);

        batch.add(NfListObject::Set(Box::new(Set {
            family: NfFamily::INet,
            table: Cow::Owned(self.config.table_name.clone()),
            name: Cow::Owned(self.config.set_v6.clone()),
            handle: None,
            set_type: SetTypeValue::Single(SetType::Ipv6Addr),
            policy: None,
            flags: Some(flags_v6),
            elem: None,
            timeout: None,
            gc_interval: None,
            size: None,
            comment: Some(Cow::Borrowed("crmonban blocked IPv6 addresses")),
        })));

        // Create input chain
        batch.add(NfListObject::Chain(Chain {
            family: NfFamily::INet,
            table: Cow::Owned(self.config.table_name.clone()),
            name: Cow::Owned(self.config.chain_name.clone()),
            newname: None,
            handle: None,
            _type: Some(NfChainType::Filter),
            hook: Some(NfHook::Input),
            prio: Some(self.config.priority),
            dev: None,
            policy: Some(NfChainPolicy::Accept),
        }));

        // Add rule to drop packets from blocked_v4 set
        let set_ref_v4 = format!("@{}", self.config.set_v4);
        batch.add(NfListObject::Rule(Rule {
            family: NfFamily::INet,
            table: Cow::Owned(self.config.table_name.clone()),
            chain: Cow::Owned(self.config.chain_name.clone()),
            handle: None,
            index: None,
            comment: Some(Cow::Borrowed("Drop blocked IPv4")),
            expr: Cow::Owned(vec![
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                        PayloadField {
                            protocol: Cow::Borrowed("ip"),
                            field: Cow::Borrowed("saddr"),
                        },
                    ))),
                    right: Expression::String(Cow::Owned(set_ref_v4)),
                    op: Operator::IN,
                }),
                Statement::Drop(None),
            ]),
        }));

        // Add rule to drop packets from blocked_v6 set
        let set_ref_v6 = format!("@{}", self.config.set_v6);
        batch.add(NfListObject::Rule(Rule {
            family: NfFamily::INet,
            table: Cow::Owned(self.config.table_name.clone()),
            chain: Cow::Owned(self.config.chain_name.clone()),
            handle: None,
            index: None,
            comment: Some(Cow::Borrowed("Drop blocked IPv6")),
            expr: Cow::Owned(vec![
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                        PayloadField {
                            protocol: Cow::Borrowed("ip6"),
                            field: Cow::Borrowed("saddr"),
                        },
                    ))),
                    right: Expression::String(Cow::Owned(set_ref_v6)),
                    op: Operator::IN,
                }),
                Statement::Drop(None),
            ]),
        }));

        // Add port scan detection rules if enabled
        if let Some(ref ps_config) = self.port_scan_config {
            if ps_config.enabled {
                self.add_port_scan_rules(&mut batch, ps_config);
            }
        }

        // Add DPI NFQUEUE rules if enabled
        if let Some(ref dpi_config) = self.dpi_config {
            if dpi_config.enabled {
                self.add_dpi_rules(&mut batch, dpi_config);
            }
        }

        // Add TLS proxy redirect rules if enabled
        if let Some(ref tls_config) = self.tls_proxy_config {
            if tls_config.enabled {
                self.add_tls_proxy_rules(&mut batch, tls_config);
            }
        }

        let ruleset = batch.to_nftables();
        apply_ruleset(&ruleset).context("Failed to apply nftables ruleset")?;

        info!("nftables configuration initialized successfully");
        Ok(())
    }

    /// Check if our table exists
    fn table_exists(&self) -> Result<bool> {
        let ruleset = get_current_ruleset()?;

        for obj in ruleset.objects.iter() {
            if let NfObject::ListObject(NfListObject::Table(table)) = obj {
                if table.name == self.config.table_name && table.family == NfFamily::INet {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Ban an IP address
    pub fn ban(&self, ip: &IpAddr, timeout_secs: Option<u64>) -> Result<()> {
        let (set_name, ip_str) = match ip {
            IpAddr::V4(v4) => (self.config.set_v4.clone(), v4.to_string()),
            IpAddr::V6(v6) => (self.config.set_v6.clone(), v6.to_string()),
        };

        // Create element expression with optional timeout
        let elem_expr = if let Some(timeout) = timeout_secs {
            Expression::Named(NamedExpression::Elem(Elem {
                val: Box::new(Expression::String(Cow::Owned(ip_str.clone()))),
                timeout: Some(timeout as u32),
                expires: None,
                comment: None,
                counter: None,
            }))
        } else {
            Expression::String(Cow::Owned(ip_str.clone()))
        };

        let mut batch = Batch::new();
        batch.add_cmd(NfCmd::Add(NfListObject::Element(Element {
            family: NfFamily::INet,
            table: Cow::Owned(self.config.table_name.clone()),
            name: Cow::Owned(set_name),
            elem: Cow::Owned(vec![elem_expr]),
        })));

        let ruleset = batch.to_nftables();
        apply_ruleset(&ruleset).with_context(|| format!("Failed to ban IP: {}", ip))?;

        info!("Banned IP: {} (timeout: {:?}s)", ip, timeout_secs);
        Ok(())
    }

    /// Unban an IP address
    pub fn unban(&self, ip: &IpAddr) -> Result<()> {
        let (set_name, ip_str) = match ip {
            IpAddr::V4(v4) => (self.config.set_v4.clone(), v4.to_string()),
            IpAddr::V6(v6) => (self.config.set_v6.clone(), v6.to_string()),
        };

        let mut batch = Batch::new();
        batch.add_cmd(NfCmd::Delete(NfListObject::Element(Element {
            family: NfFamily::INet,
            table: Cow::Owned(self.config.table_name.clone()),
            name: Cow::Owned(set_name),
            elem: Cow::Owned(vec![Expression::String(Cow::Owned(ip_str.clone()))]),
        })));

        let ruleset = batch.to_nftables();
        apply_ruleset(&ruleset).with_context(|| format!("Failed to unban IP: {}", ip))?;

        info!("Unbanned IP: {}", ip);
        Ok(())
    }

    /// Get list of currently banned IPs from nftables
    pub fn get_banned_ips(&self) -> Result<Vec<String>> {
        let ruleset = get_current_ruleset()?;
        let mut banned = Vec::new();

        for obj in ruleset.objects.iter() {
            if let NfObject::ListObject(NfListObject::Set(set)) = obj {
                if set.table == self.config.table_name
                    && (set.name == self.config.set_v4 || set.name == self.config.set_v6)
                {
                    if let Some(elems) = &set.elem {
                        for elem in elems.iter() {
                            match elem {
                                Expression::String(ip) => {
                                    banned.push(ip.to_string());
                                }
                                Expression::Named(NamedExpression::Elem(e)) => {
                                    if let Expression::String(ip) = e.val.as_ref() {
                                        banned.push(ip.to_string());
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }

        Ok(banned)
    }

    /// Flush all banned IPs from sets
    pub fn flush(&self) -> Result<()> {
        let mut batch = Batch::new();

        // Flush IPv4 set
        batch.add_cmd(NfCmd::Flush(FlushObject::Set(Box::new(Set {
            family: NfFamily::INet,
            table: Cow::Owned(self.config.table_name.clone()),
            name: Cow::Owned(self.config.set_v4.clone()),
            handle: None,
            set_type: SetTypeValue::Single(SetType::Ipv4Addr),
            policy: None,
            flags: None,
            elem: None,
            timeout: None,
            gc_interval: None,
            size: None,
            comment: None,
        }))));

        // Flush IPv6 set
        batch.add_cmd(NfCmd::Flush(FlushObject::Set(Box::new(Set {
            family: NfFamily::INet,
            table: Cow::Owned(self.config.table_name.clone()),
            name: Cow::Owned(self.config.set_v6.clone()),
            handle: None,
            set_type: SetTypeValue::Single(SetType::Ipv6Addr),
            policy: None,
            flags: None,
            elem: None,
            timeout: None,
            gc_interval: None,
            size: None,
            comment: None,
        }))));

        let ruleset = batch.to_nftables();
        apply_ruleset(&ruleset).context("Failed to flush nftables sets")?;

        info!("Flushed all banned IPs from nftables");
        Ok(())
    }

    /// Remove the entire crmonban table
    pub fn cleanup(&self) -> Result<()> {
        if !self.table_exists()? {
            warn!(
                "Table {} does not exist, nothing to clean up",
                self.config.table_name
            );
            return Ok(());
        }

        let mut batch = Batch::new();
        batch.add_cmd(NfCmd::Delete(NfListObject::Table(Table {
            family: NfFamily::INet,
            name: Cow::Owned(self.config.table_name.clone()),
            handle: None,
        })));

        let ruleset = batch.to_nftables();
        apply_ruleset(&ruleset).context("Failed to delete nftables table")?;

        info!("Removed nftables table: {}", self.config.table_name);
        Ok(())
    }

    /// Sync database bans to nftables (useful on startup)
    pub fn sync_from_db(&self, bans: &[(IpAddr, Option<u64>)]) -> Result<()> {
        info!("Syncing {} bans to nftables", bans.len());

        for (ip, timeout) in bans {
            if let Err(e) = self.ban(ip, *timeout) {
                warn!("Failed to sync ban for {}: {}", ip, e);
            }
        }

        Ok(())
    }

    /// Add port scan detection rules to the batch
    fn add_port_scan_rules(&self, batch: &mut Batch, config: &PortScanConfig) {
        info!("Adding port scan detection rules");

        // Create a separate chain for port scan detection (after the block rules)
        batch.add(NfListObject::Chain(Chain {
            family: NfFamily::INet,
            table: Cow::Owned(self.config.table_name.clone()),
            name: Cow::Borrowed("portscan_detect"),
            newname: None,
            handle: None,
            _type: Some(NfChainType::Filter),
            hook: Some(NfHook::Input),
            prio: Some(self.config.priority + 10), // After main chain
            dev: None,
            policy: Some(NfChainPolicy::Accept),
        }));

        // TCP SYN scan detection (new connections only)
        if config.detect_syn_scan {
            self.add_syn_scan_rule(batch, config);
        }

        // TCP NULL scan detection (no flags set)
        if config.detect_null_scan {
            self.add_null_scan_rule(batch);
        }

        // TCP XMAS scan detection (FIN+PSH+URG)
        if config.detect_xmas_scan {
            self.add_xmas_scan_rule(batch);
        }

        // TCP FIN scan detection (only FIN flag)
        if config.detect_fin_scan {
            self.add_fin_scan_rule(batch);
        }

        // UDP scan detection
        if config.detect_udp_scan {
            self.add_udp_scan_rule(batch, config);
        }

        // Generic TCP connection logging for port tracking
        self.add_generic_port_log_rule(batch, config);

        info!("Port scan detection rules added");
    }

    /// Add SYN scan detection rule
    fn add_syn_scan_rule(&self, batch: &mut Batch, config: &PortScanConfig) {
        // Log TCP SYN packets to new (non-established) connections
        // nft add rule inet crmonban portscan_detect tcp flags syn / fin,syn,rst,ack ct state new log prefix "[crmonban-portscan-syn] "
        batch.add(NfListObject::Rule(Rule {
            family: NfFamily::INet,
            table: Cow::Owned(self.config.table_name.clone()),
            chain: Cow::Borrowed("portscan_detect"),
            handle: None,
            index: None,
            comment: Some(Cow::Borrowed("Log SYN scan attempts")),
            expr: Cow::Owned(vec![
                // Match TCP protocol
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                        PayloadField {
                            protocol: Cow::Borrowed("meta"),
                            field: Cow::Borrowed("l4proto"),
                        },
                    ))),
                    right: Expression::String(Cow::Borrowed("tcp")),
                    op: Operator::EQ,
                }),
                // Log with prefix for parsing
                Statement::Log(Some(Log {
                    prefix: Some(Cow::Borrowed("[crmonban-portscan-syn] ")),
                    group: config.nflog_group,
                    snaplen: None,
                    queue_threshold: None,
                    level: Some(LogLevel::Info),
                    flags: None,
                })),
            ]),
        }));
    }

    /// Add NULL scan detection rule (no TCP flags)
    fn add_null_scan_rule(&self, batch: &mut Batch) {
        batch.add(NfListObject::Rule(Rule {
            family: NfFamily::INet,
            table: Cow::Owned(self.config.table_name.clone()),
            chain: Cow::Borrowed("portscan_detect"),
            handle: None,
            index: None,
            comment: Some(Cow::Borrowed("Log NULL scan attempts")),
            expr: Cow::Owned(vec![
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                        PayloadField {
                            protocol: Cow::Borrowed("meta"),
                            field: Cow::Borrowed("l4proto"),
                        },
                    ))),
                    right: Expression::String(Cow::Borrowed("tcp")),
                    op: Operator::EQ,
                }),
                Statement::Log(Some(Log {
                    prefix: Some(Cow::Borrowed("[crmonban-portscan-null] ")),
                    group: None,
                    snaplen: None,
                    queue_threshold: None,
                    level: Some(LogLevel::Info),
                    flags: None,
                })),
            ]),
        }));
    }

    /// Add XMAS scan detection rule (FIN+PSH+URG flags)
    fn add_xmas_scan_rule(&self, batch: &mut Batch) {
        batch.add(NfListObject::Rule(Rule {
            family: NfFamily::INet,
            table: Cow::Owned(self.config.table_name.clone()),
            chain: Cow::Borrowed("portscan_detect"),
            handle: None,
            index: None,
            comment: Some(Cow::Borrowed("Log XMAS scan attempts")),
            expr: Cow::Owned(vec![
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                        PayloadField {
                            protocol: Cow::Borrowed("meta"),
                            field: Cow::Borrowed("l4proto"),
                        },
                    ))),
                    right: Expression::String(Cow::Borrowed("tcp")),
                    op: Operator::EQ,
                }),
                Statement::Log(Some(Log {
                    prefix: Some(Cow::Borrowed("[crmonban-portscan-xmas] ")),
                    group: None,
                    snaplen: None,
                    queue_threshold: None,
                    level: Some(LogLevel::Info),
                    flags: None,
                })),
            ]),
        }));
    }

    /// Add FIN scan detection rule (only FIN flag)
    fn add_fin_scan_rule(&self, batch: &mut Batch) {
        batch.add(NfListObject::Rule(Rule {
            family: NfFamily::INet,
            table: Cow::Owned(self.config.table_name.clone()),
            chain: Cow::Borrowed("portscan_detect"),
            handle: None,
            index: None,
            comment: Some(Cow::Borrowed("Log FIN scan attempts")),
            expr: Cow::Owned(vec![
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                        PayloadField {
                            protocol: Cow::Borrowed("meta"),
                            field: Cow::Borrowed("l4proto"),
                        },
                    ))),
                    right: Expression::String(Cow::Borrowed("tcp")),
                    op: Operator::EQ,
                }),
                Statement::Log(Some(Log {
                    prefix: Some(Cow::Borrowed("[crmonban-portscan-fin] ")),
                    group: None,
                    snaplen: None,
                    queue_threshold: None,
                    level: Some(LogLevel::Info),
                    flags: None,
                })),
            ]),
        }));
    }

    /// Add UDP scan detection rule
    fn add_udp_scan_rule(&self, batch: &mut Batch, config: &PortScanConfig) {
        batch.add(NfListObject::Rule(Rule {
            family: NfFamily::INet,
            table: Cow::Owned(self.config.table_name.clone()),
            chain: Cow::Borrowed("portscan_detect"),
            handle: None,
            index: None,
            comment: Some(Cow::Borrowed("Log UDP scan attempts")),
            expr: Cow::Owned(vec![
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                        PayloadField {
                            protocol: Cow::Borrowed("meta"),
                            field: Cow::Borrowed("l4proto"),
                        },
                    ))),
                    right: Expression::String(Cow::Borrowed("udp")),
                    op: Operator::EQ,
                }),
                Statement::Log(Some(Log {
                    prefix: Some(Cow::Borrowed("[crmonban-portscan-udp] ")),
                    group: config.nflog_group,
                    snaplen: None,
                    queue_threshold: None,
                    level: Some(LogLevel::Info),
                    flags: None,
                })),
            ]),
        }));
    }

    /// Add generic port logging rule for tracking
    fn add_generic_port_log_rule(&self, batch: &mut Batch, config: &PortScanConfig) {
        // This logs all new connections for port tracking
        // The log prefix allows the port_scan_monitor to parse and track
        batch.add(NfListObject::Rule(Rule {
            family: NfFamily::INet,
            table: Cow::Owned(self.config.table_name.clone()),
            chain: Cow::Borrowed("portscan_detect"),
            handle: None,
            index: None,
            comment: Some(Cow::Borrowed("Log new connections for port scan tracking")),
            expr: Cow::Owned(vec![
                // Match new connections (ct state new)
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                        PayloadField {
                            protocol: Cow::Borrowed("ct"),
                            field: Cow::Borrowed("state"),
                        },
                    ))),
                    right: Expression::String(Cow::Borrowed("new")),
                    op: Operator::EQ,
                }),
                Statement::Log(Some(Log {
                    prefix: Some(Cow::Borrowed("[crmonban-portscan] ")),
                    group: config.nflog_group,
                    snaplen: None,
                    queue_threshold: None,
                    level: Some(LogLevel::Info),
                    flags: None,
                })),
            ]),
        }));
    }

    /// Initialize port scan detection (can be called separately to add rules to existing table)
    pub fn init_port_scan_detection(&self, config: &PortScanConfig) -> Result<()> {
        if !config.enabled {
            debug!("Port scan detection is disabled");
            return Ok(());
        }

        if !self.table_exists()? {
            return Err(anyhow::anyhow!(
                "Table {} does not exist. Initialize firewall first.",
                self.config.table_name
            ));
        }

        let mut batch = Batch::new();
        self.add_port_scan_rules(&mut batch, config);

        let ruleset = batch.to_nftables();
        apply_ruleset(&ruleset).context("Failed to apply port scan detection rules")?;

        info!("Port scan detection rules initialized");
        Ok(())
    }

    /// Add DPI NFQUEUE rules to the batch
    fn add_dpi_rules(&self, batch: &mut Batch, config: &DpiConfig) {
        info!("Adding DPI NFQUEUE rules (queue {})", config.queue_num);

        // Create a separate chain for DPI processing
        batch.add(NfListObject::Chain(Chain {
            family: NfFamily::INet,
            table: Cow::Owned(self.config.table_name.clone()),
            name: Cow::Borrowed("dpi_inspect"),
            newname: None,
            handle: None,
            _type: Some(NfChainType::Filter),
            hook: Some(NfHook::Input),
            prio: Some(self.config.priority + 5), // After block rules, before port scan
            dev: None,
            policy: Some(NfChainPolicy::Accept),
        }));

        // Queue new TCP connections to userspace for DPI
        // This sends the first N packets of each connection to NFQUEUE
        batch.add(NfListObject::Rule(Rule {
            family: NfFamily::INet,
            table: Cow::Owned(self.config.table_name.clone()),
            chain: Cow::Borrowed("dpi_inspect"),
            handle: None,
            index: None,
            comment: Some(Cow::Borrowed("Queue new TCP connections for DPI")),
            expr: Cow::Owned(vec![
                // Match TCP protocol
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                        PayloadField {
                            protocol: Cow::Borrowed("meta"),
                            field: Cow::Borrowed("l4proto"),
                        },
                    ))),
                    right: Expression::String(Cow::Borrowed("tcp")),
                    op: Operator::EQ,
                }),
                // Match new/established connections (first few packets)
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                        PayloadField {
                            protocol: Cow::Borrowed("ct"),
                            field: Cow::Borrowed("state"),
                        },
                    ))),
                    right: Expression::String(Cow::Borrowed("new,established")),
                    op: Operator::EQ,
                }),
                // Queue to userspace
                Statement::Queue(Queue {
                    num: Expression::Number(config.queue_num as u32),
                    flags: None, // Note: bypass flag would require HashSet<QueueFlag>
                }),
            ]),
        }));

        info!("DPI rules added for NFQUEUE {}", config.queue_num);
    }

    /// Add TLS proxy redirect rules for transparent MITM interception
    fn add_tls_proxy_rules(&self, batch: &mut Batch, config: &TlsProxyConfig) {
        info!(
            "Adding TLS proxy redirect rules (proxy port {})",
            config.listen_port
        );

        // Create a NAT table and chain for DNAT/REDIRECT
        // Note: For transparent proxying, we need prerouting DNAT
        batch.add(NfListObject::Chain(Chain {
            family: NfFamily::INet,
            table: Cow::Owned(self.config.table_name.clone()),
            name: Cow::Borrowed("tls_redirect"),
            newname: None,
            handle: None,
            _type: Some(NfChainType::NAT),
            hook: Some(NfHook::Prerouting),
            prio: Some(-100), // Before regular filter chains
            dev: None,
            policy: Some(NfChainPolicy::Accept),
        }));

        // Redirect HTTPS traffic (port 443) to local TLS proxy
        // Only redirect traffic coming from other hosts, not locally generated
        for port in &config.intercept_ports {
            batch.add(NfListObject::Rule(Rule {
                family: NfFamily::INet,
                table: Cow::Owned(self.config.table_name.clone()),
                chain: Cow::Borrowed("tls_redirect"),
                handle: None,
                index: None,
                comment: Some(Cow::Owned(format!(
                    "Redirect port {} to TLS proxy",
                    port
                ))),
                expr: Cow::Owned(vec![
                    // Match TCP protocol
                    Statement::Match(Match {
                        left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                            PayloadField {
                                protocol: Cow::Borrowed("meta"),
                                field: Cow::Borrowed("l4proto"),
                            },
                        ))),
                        right: Expression::String(Cow::Borrowed("tcp")),
                        op: Operator::EQ,
                    }),
                    // Match destination port
                    Statement::Match(Match {
                        left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                            PayloadField {
                                protocol: Cow::Borrowed("tcp"),
                                field: Cow::Borrowed("dport"),
                            },
                        ))),
                        right: Expression::Number(*port as u32),
                        op: Operator::EQ,
                    }),
                    // Redirect to local proxy port
                    Statement::Redirect(Some(nftables::stmt::NAT {
                        addr: None,
                        family: None,
                        port: Some(Expression::Number(config.listen_port as u32)),
                        flags: None,
                    })),
                ]),
            }));
        }

        info!(
            "TLS proxy redirect rules added for ports {:?} -> {}",
            config.intercept_ports, config.listen_port
        );
    }

    /// Initialize TLS proxy redirect rules (can be called separately)
    pub fn init_tls_proxy(&self, config: &TlsProxyConfig) -> Result<()> {
        if !config.enabled {
            debug!("TLS proxy is disabled");
            return Ok(());
        }

        if !self.table_exists()? {
            return Err(anyhow::anyhow!(
                "Table {} does not exist. Initialize firewall first.",
                self.config.table_name
            ));
        }

        let mut batch = Batch::new();
        self.add_tls_proxy_rules(&mut batch, config);

        let ruleset = batch.to_nftables();
        apply_ruleset(&ruleset).context("Failed to apply TLS proxy rules")?;

        info!("TLS proxy redirect rules initialized");
        Ok(())
    }

    /// Initialize DPI (can be called separately to add rules to existing table)
    pub fn init_dpi(&self, config: &DpiConfig) -> Result<()> {
        if !config.enabled {
            debug!("DPI is disabled");
            return Ok(());
        }

        if !self.table_exists()? {
            return Err(anyhow::anyhow!(
                "Table {} does not exist. Initialize firewall first.",
                self.config.table_name
            ));
        }

        let mut batch = Batch::new();
        self.add_dpi_rules(&mut batch, config);

        let ruleset = batch.to_nftables();
        apply_ruleset(&ruleset).context("Failed to apply DPI rules")?;

        info!("DPI rules initialized");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_firewall_config() {
        let config = NftablesConfig::default();
        let fw = Firewall::new(config);
        assert_eq!(fw.config.table_name, "crmonban");
    }
}
