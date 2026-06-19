use anyhow::{Context, Result};
use nftables::{
    batch::Batch,
    expr::{Elem, Expression, NamedExpression, Payload, PayloadField, Range},
    helper::{apply_ruleset, get_current_ruleset_with_args, DEFAULT_NFT},
    schema::{
        Chain, Element, FlushObject, NfCmd, NfListObject, NfObject, Rule, Set, SetFlag,
        SetType, SetTypeValue, Table,
    },
    stmt::{Counter, Limit, Log, LogLevel, Match, Operator, Queue, QueueFlag, Statement},
    types::{NfChainPolicy, NfChainType, NfFamily, NfHook},
};
use std::borrow::Cow;
use std::collections::HashSet;
use std::net::IpAddr;
use tracing::{debug, info, warn};

use crate::config::{DeploymentConfig, DeploymentMode, DpiConfig, NatMode, NftablesConfig, PortAction, PortRule, PortRulesConfig, PortScanConfig, TlsProxyConfig};

/// Firewall manager for nftables operations
/// nft set names for the inline-DPI source whitelist (interval/CIDR-capable).
/// Whitelisted sources are accepted in the dpi_inspect chain before the NFQUEUE,
/// so they are never queued or inline-dropped by the engine.
const DPI_ALLOW_SET_V4: &str = "dpi_allow_v4";
const DPI_ALLOW_SET_V6: &str = "dpi_allow_v6";

/// Conntrack/packet mark applied to a flow once the engine judges it good, so the
/// kernel bypasses (accepts) the rest of the flow without re-queuing it. Single
/// high bit to avoid colliding with low-valued routing marks; sets the full mark
/// for now (masking + making it configurable is a follow-up).
pub const DPI_GOOD_MARK: u32 = 0x4000_0000;

/// True if `s` is a literal IP address or `addr/prefix` CIDR — i.e. something nft
/// can add to an interval set WITHOUT a DNS lookup. Used to filter the inline-DPI
/// allow entries so a stray hostname can't fail the whole atomic batch.
fn is_ip_or_cidr(s: &str) -> bool {
    if s.parse::<IpAddr>().is_ok() {
        return true;
    }
    match s.split_once('/') {
        Some((addr, prefix)) => {
            let ok_addr = addr.parse::<IpAddr>();
            match ok_addr {
                Ok(IpAddr::V4(_)) => prefix.parse::<u8>().map(|p| p <= 32).unwrap_or(false),
                Ok(IpAddr::V6(_)) => prefix.parse::<u8>().map(|p| p <= 128).unwrap_or(false),
                Err(_) => false,
            }
        }
        None => false,
    }
}

pub struct Firewall {
    config: NftablesConfig,
    deployment: DeploymentConfig,
    port_scan_config: Option<PortScanConfig>,
    dpi_config: Option<DpiConfig>,
    tls_proxy_config: Option<TlsProxyConfig>,
    port_rules_config: Option<PortRulesConfig>,
}

impl Firewall {
    /// Create a new firewall manager
    pub fn new(config: NftablesConfig) -> Self {
        Self {
            config,
            deployment: DeploymentConfig::default(),
            port_scan_config: None,
            dpi_config: None,
            tls_proxy_config: None,
            port_rules_config: None,
        }
    }

    /// Create a new firewall manager with deployment mode
    pub fn with_deployment(config: NftablesConfig, deployment: DeploymentConfig) -> Self {
        Self {
            config,
            deployment,
            port_scan_config: None,
            dpi_config: None,
            tls_proxy_config: None,
            port_rules_config: None,
        }
    }

    /// Create a new firewall manager with port scan detection
    pub fn with_port_scan(config: NftablesConfig, port_scan_config: PortScanConfig) -> Self {
        Self {
            config,
            deployment: DeploymentConfig::default(),
            port_scan_config: Some(port_scan_config),
            dpi_config: None,
            tls_proxy_config: None,
            port_rules_config: None,
        }
    }

    /// Create a new firewall manager with all features
    pub fn with_features(
        config: NftablesConfig,
        port_scan_config: Option<PortScanConfig>,
        dpi_config: Option<DpiConfig>,
        tls_proxy_config: Option<TlsProxyConfig>,
        port_rules_config: Option<PortRulesConfig>,
    ) -> Self {
        Self {
            config,
            deployment: DeploymentConfig::default(),
            port_scan_config,
            dpi_config,
            tls_proxy_config,
            port_rules_config,
        }
    }

    /// Create a new firewall manager with all features and deployment config
    pub fn with_all(
        config: NftablesConfig,
        deployment: DeploymentConfig,
        port_scan_config: Option<PortScanConfig>,
        dpi_config: Option<DpiConfig>,
        tls_proxy_config: Option<TlsProxyConfig>,
        port_rules_config: Option<PortRulesConfig>,
    ) -> Self {
        Self {
            config,
            deployment,
            port_scan_config,
            dpi_config,
            tls_proxy_config,
            port_rules_config,
        }
    }

    /// Get the deployment mode
    pub fn deployment_mode(&self) -> DeploymentMode {
        self.deployment.mode
    }

    /// Initialize nftables table, chains, and sets
    pub fn init(&self) -> Result<()> {
        info!("Initializing nftables configuration");

        let mut batch = Batch::new();

        // Reconcile: if our table already exists, delete it first (atomically, in
        // this same batch) and rebuild from scratch, so config changes — the
        // NFQUEUE number, the DPI/allow rules, the deployment mode — actually take
        // effect on restart instead of being skipped. Bans are restored from the
        // DB by sync_bans() right after init(), and the whitelist/CF allow set by
        // sync_dpi_allow(); the delete+rebuild is one atomic apply, so there is no
        // window with a half-built table.
        if self.table_exists()? {
            debug!(
                "Table {} exists; rebuilding to apply current config",
                self.config.table_name
            );
            batch.add_cmd(NfCmd::Delete(NfListObject::Table(Table {
                family: NfFamily::INet,
                name: Cow::Owned(self.config.table_name.clone()),
                handle: None,
            })));
        }

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

        // Create inline-DPI whitelist sets (interval/CIDR-capable). Sources here
        // are accepted before the NFQUEUE so they are never inline-dropped.
        let mut allow_flags_v4 = HashSet::new();
        allow_flags_v4.insert(SetFlag::Interval);
        batch.add(NfListObject::Set(Box::new(Set {
            family: NfFamily::INet,
            table: Cow::Owned(self.config.table_name.clone()),
            name: Cow::Borrowed(DPI_ALLOW_SET_V4),
            handle: None,
            set_type: SetTypeValue::Single(SetType::Ipv4Addr),
            policy: None,
            flags: Some(allow_flags_v4),
            elem: None,
            timeout: None,
            gc_interval: None,
            size: None,
            comment: Some(Cow::Borrowed("crmonban inline-DPI whitelist IPv4")),
        })));

        let mut allow_flags_v6 = HashSet::new();
        allow_flags_v6.insert(SetFlag::Interval);
        batch.add(NfListObject::Set(Box::new(Set {
            family: NfFamily::INet,
            table: Cow::Owned(self.config.table_name.clone()),
            name: Cow::Borrowed(DPI_ALLOW_SET_V6),
            handle: None,
            set_type: SetTypeValue::Single(SetType::Ipv6Addr),
            policy: None,
            flags: Some(allow_flags_v6),
            elem: None,
            timeout: None,
            gc_interval: None,
            size: None,
            comment: Some(Cow::Borrowed("crmonban inline-DPI whitelist IPv6")),
        })));

        // Create chains based on deployment mode
        info!(
            "Deployment mode: {} (input={}, forward={})",
            self.deployment.mode,
            self.deployment.has_input_protection(),
            self.deployment.has_forward_protection()
        );

        let set_ref_v4 = format!("@{}", self.config.set_v4);
        let set_ref_v6 = format!("@{}", self.config.set_v6);

        // Create INPUT chain for host protection
        if self.deployment.has_input_protection() {
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

            // Add rule to drop packets from blocked_v4 set on INPUT
            batch.add(NfListObject::Rule(Rule {
                family: NfFamily::INet,
                table: Cow::Owned(self.config.table_name.clone()),
                chain: Cow::Owned(self.config.chain_name.clone()),
                handle: None,
                index: None,
                comment: Some(Cow::Borrowed("Drop blocked IPv4 (input)")),
                expr: Cow::Owned(vec![
                    Statement::Match(Match {
                        left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                            PayloadField {
                                protocol: Cow::Borrowed("ip"),
                                field: Cow::Borrowed("saddr"),
                            },
                        ))),
                        right: Expression::String(Cow::Owned(set_ref_v4.clone())),
                        op: Operator::IN,
                    }),
                    // Counter = packets dropped because their source is banned.
                    Statement::Counter(Counter::Anonymous(None)),
                    Statement::Drop(None),
                ]),
            }));

            // Add rule to drop packets from blocked_v6 set on INPUT
            batch.add(NfListObject::Rule(Rule {
                family: NfFamily::INet,
                table: Cow::Owned(self.config.table_name.clone()),
                chain: Cow::Owned(self.config.chain_name.clone()),
                handle: None,
                index: None,
                comment: Some(Cow::Borrowed("Drop blocked IPv6 (input)")),
                expr: Cow::Owned(vec![
                    Statement::Match(Match {
                        left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                            PayloadField {
                                protocol: Cow::Borrowed("ip6"),
                                field: Cow::Borrowed("saddr"),
                            },
                        ))),
                        right: Expression::String(Cow::Owned(set_ref_v6.clone())),
                        op: Operator::IN,
                    }),
                    Statement::Counter(Counter::Anonymous(None)),
                    Statement::Drop(None),
                ]),
            }));
        }

        // Create FORWARD chain for network filtering (Gateway mode)
        if self.deployment.has_forward_protection() {
            let forward_chain_name = format!("{}_forward", self.config.chain_name);

            batch.add(NfListObject::Chain(Chain {
                family: NfFamily::INet,
                table: Cow::Owned(self.config.table_name.clone()),
                name: Cow::Owned(forward_chain_name.clone()),
                newname: None,
                handle: None,
                _type: Some(NfChainType::Filter),
                hook: Some(NfHook::Forward),
                prio: Some(self.config.priority),
                dev: None,
                policy: Some(NfChainPolicy::Accept),
            }));

            // Add rule to drop packets from blocked_v4 set on FORWARD
            batch.add(NfListObject::Rule(Rule {
                family: NfFamily::INet,
                table: Cow::Owned(self.config.table_name.clone()),
                chain: Cow::Owned(forward_chain_name.clone()),
                handle: None,
                index: None,
                comment: Some(Cow::Borrowed("Drop blocked IPv4 (forward)")),
                expr: Cow::Owned(vec![
                    Statement::Match(Match {
                        left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                            PayloadField {
                                protocol: Cow::Borrowed("ip"),
                                field: Cow::Borrowed("saddr"),
                            },
                        ))),
                        right: Expression::String(Cow::Owned(set_ref_v4.clone())),
                        op: Operator::IN,
                    }),
                    // Counter = packets dropped because their source is banned.
                    Statement::Counter(Counter::Anonymous(None)),
                    Statement::Drop(None),
                ]),
            }));

            // Add rule to drop packets from blocked_v6 set on FORWARD
            batch.add(NfListObject::Rule(Rule {
                family: NfFamily::INet,
                table: Cow::Owned(self.config.table_name.clone()),
                chain: Cow::Owned(forward_chain_name.clone()),
                handle: None,
                index: None,
                comment: Some(Cow::Borrowed("Drop blocked IPv6 (forward)")),
                expr: Cow::Owned(vec![
                    Statement::Match(Match {
                        left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                            PayloadField {
                                protocol: Cow::Borrowed("ip6"),
                                field: Cow::Borrowed("saddr"),
                            },
                        ))),
                        right: Expression::String(Cow::Owned(set_ref_v6.clone())),
                        op: Operator::IN,
                    }),
                    Statement::Counter(Counter::Anonymous(None)),
                    Statement::Drop(None),
                ]),
            }));

            // For gateway-only mode (no INPUT chain created), create a minimal one for the other rules
            if !self.deployment.has_input_protection() {
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
            }

            // Add NAT rules if configured
            self.add_nat_rules(&mut batch);
        }

        // Create OUTPUT chain for HostLite mode (unauthorized traffic detection)
        if self.deployment.has_output_protection() {
            let output_chain_name = format!("{}_output", self.config.chain_name);

            info!("Creating OUTPUT chain for outbound traffic monitoring");

            // Create allowed outbound destinations set (IPv4)
            let mut flags_outbound_v4 = HashSet::new();
            flags_outbound_v4.insert(SetFlag::Interval);

            batch.add(NfListObject::Set(Box::new(Set {
                family: NfFamily::INet,
                table: Cow::Owned(self.config.table_name.clone()),
                name: Cow::Borrowed("allowed_outbound_v4"),
                handle: None,
                set_type: SetTypeValue::Single(SetType::Ipv4Addr),
                policy: None,
                flags: Some(flags_outbound_v4),
                elem: None,
                timeout: None,
                gc_interval: None,
                size: None,
                comment: Some(Cow::Borrowed("crmonban allowed outbound IPv4 destinations")),
            })));

            // Create allowed outbound destinations set (IPv6)
            let mut flags_outbound_v6 = HashSet::new();
            flags_outbound_v6.insert(SetFlag::Interval);

            batch.add(NfListObject::Set(Box::new(Set {
                family: NfFamily::INet,
                table: Cow::Owned(self.config.table_name.clone()),
                name: Cow::Borrowed("allowed_outbound_v6"),
                handle: None,
                set_type: SetTypeValue::Single(SetType::Ipv6Addr),
                policy: None,
                flags: Some(flags_outbound_v6),
                elem: None,
                timeout: None,
                gc_interval: None,
                size: None,
                comment: Some(Cow::Borrowed("crmonban allowed outbound IPv6 destinations")),
            })));

            // Create OUTPUT chain
            batch.add(NfListObject::Chain(Chain {
                family: NfFamily::INet,
                table: Cow::Owned(self.config.table_name.clone()),
                name: Cow::Owned(output_chain_name.clone()),
                newname: None,
                handle: None,
                _type: Some(NfChainType::Filter),
                hook: Some(NfHook::Output),
                prio: Some(self.config.priority),
                dev: None,
                policy: Some(NfChainPolicy::Accept),
            }));

            // Add logging rule for new outbound connections (ct state new)
            batch.add(NfListObject::Rule(Rule {
                family: NfFamily::INet,
                table: Cow::Owned(self.config.table_name.clone()),
                chain: Cow::Owned(output_chain_name.clone()),
                handle: None,
                index: None,
                comment: Some(Cow::Borrowed("Log new outbound connections")),
                expr: Cow::Owned(vec![
                    // Match ct state new
                    Statement::Match(Match {
                        left: Expression::Named(NamedExpression::CT(nftables::expr::CT {
                            key: Cow::Borrowed("state"),
                            family: None,
                            dir: None,
                        })),
                        right: Expression::String(Cow::Borrowed("new")),
                        op: Operator::EQ,
                    }),
                    // Log the connection
                    Statement::Log(Some(Log {
                        prefix: Some(Cow::Borrowed("[crmonban-output] ")),
                        group: None,
                        snaplen: None,
                        queue_threshold: None,
                        level: Some(LogLevel::Info),
                        flags: None,
                    })),
                ]),
            }));

            // If output_action is Block, add rules to drop non-allowlisted destinations
            if self.deployment.output_action == crate::config::OutputAction::Block {
                // Drop IPv4 not in allowlist
                batch.add(NfListObject::Rule(Rule {
                    family: NfFamily::INet,
                    table: Cow::Owned(self.config.table_name.clone()),
                    chain: Cow::Owned(output_chain_name.clone()),
                    handle: None,
                    index: None,
                    comment: Some(Cow::Borrowed("Block unauthorized outbound IPv4")),
                    expr: Cow::Owned(vec![
                        // Match ct state new
                        Statement::Match(Match {
                            left: Expression::Named(NamedExpression::CT(nftables::expr::CT {
                                key: Cow::Borrowed("state"),
                                family: None,
                                dir: None,
                            })),
                            right: Expression::String(Cow::Borrowed("new")),
                            op: Operator::EQ,
                        }),
                        // Match destination NOT in allowed set
                        Statement::Match(Match {
                            left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                                PayloadField {
                                    protocol: Cow::Borrowed("ip"),
                                    field: Cow::Borrowed("daddr"),
                                },
                            ))),
                            right: Expression::String(Cow::Borrowed("@allowed_outbound_v4")),
                            op: Operator::NEQ,
                        }),
                        Statement::Drop(None),
                    ]),
                }));

                // Drop IPv6 not in allowlist
                batch.add(NfListObject::Rule(Rule {
                    family: NfFamily::INet,
                    table: Cow::Owned(self.config.table_name.clone()),
                    chain: Cow::Owned(output_chain_name.clone()),
                    handle: None,
                    index: None,
                    comment: Some(Cow::Borrowed("Block unauthorized outbound IPv6")),
                    expr: Cow::Owned(vec![
                        // Match ct state new
                        Statement::Match(Match {
                            left: Expression::Named(NamedExpression::CT(nftables::expr::CT {
                                key: Cow::Borrowed("state"),
                                family: None,
                                dir: None,
                            })),
                            right: Expression::String(Cow::Borrowed("new")),
                            op: Operator::EQ,
                        }),
                        // Match destination NOT in allowed set
                        Statement::Match(Match {
                            left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                                PayloadField {
                                    protocol: Cow::Borrowed("ip6"),
                                    field: Cow::Borrowed("daddr"),
                                },
                            ))),
                            right: Expression::String(Cow::Borrowed("@allowed_outbound_v6")),
                            op: Operator::NEQ,
                        }),
                        Statement::Drop(None),
                    ]),
                }));
            }

            // Populate allowlist from config
            self.init_outbound_allowlist(&mut batch);
        }

        // Add port scan detection rules if enabled
        if let Some(ref ps_config) = self.port_scan_config {
            if ps_config.enabled {
                self.add_port_scan_rules(&mut batch, ps_config);
            }
        }

        // Add DPI NFQUEUE rules if enabled
        if let Some(ref dpi_config) = self.dpi_config {
            if dpi_config.enabled {
                self.add_dpi_rules(&mut batch, dpi_config); // INPUT chain
                // Gateway deployments also inspect transit (forward) traffic on a
                // separate base chain. Deferred on host-only / Docker boxes where
                // all forward traffic would otherwise be funnelled to userspace.
                if self.deployment.has_forward_protection() {
                    self.add_dpi_chain(
                        &mut batch,
                        "dpi_inspect_forward",
                        NfHook::Forward,
                        dpi_config,
                    );
                }
            }
        }

        // Add TLS proxy redirect rules if enabled
        if let Some(ref tls_config) = self.tls_proxy_config {
            if tls_config.enabled {
                self.add_tls_proxy_rules(&mut batch, tls_config);
            }
        }

        // Add port rules (UFW-like) if enabled
        if let Some(ref port_rules) = self.port_rules_config {
            if port_rules.enabled {
                self.add_port_rules(&mut batch, port_rules);
            }
        }

        let ruleset = batch.to_nftables();
        apply_ruleset(&ruleset).context("Failed to apply nftables ruleset")?;

        info!("nftables configuration initialized successfully");
        Ok(())
    }

    /// Check if our table exists
    fn table_exists(&self) -> Result<bool> {
        // List ONLY tables (no chains/rules). Listing the full ruleset would force
        // the nftables crate to deserialize our own NFQUEUE rule, whose single
        // queue flag nft renders as `"flags":"bypass"` (a bare string) — a form
        // this crate version can't parse, so a full read-back of a live crmonban
        // table fails. Tables-only JSON has no statements and sidesteps that.
        let args = ["list", "tables", "inet"];
        let ruleset = get_current_ruleset_with_args(DEFAULT_NFT, args.iter())
            .context("Failed to list nftables tables")?;

        for obj in ruleset.objects.iter() {
            if let NfObject::ListObject(NfListObject::Table(table)) = obj {
                if table.name == self.config.table_name && table.family == NfFamily::INet {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Add NAT rules for filter/edge deployments
    fn add_nat_rules(&self, batch: &mut Batch) {
        if self.deployment.nat_mode == NatMode::None {
            return;
        }

        // Create NAT table and postrouting chain
        let nat_chain_name = format!("{}_nat", self.config.chain_name);

        batch.add(NfListObject::Chain(Chain {
            family: NfFamily::INet,
            table: Cow::Owned(self.config.table_name.clone()),
            name: Cow::Owned(nat_chain_name.clone()),
            newname: None,
            handle: None,
            _type: Some(NfChainType::NAT),
            hook: Some(NfHook::Postrouting),
            prio: Some(100), // NAT priority
            dev: None,
            policy: Some(NfChainPolicy::Accept),
        }));

        // Add masquerade rule for outgoing traffic on external interfaces
        for iface in &self.deployment.external_interfaces {
            match self.deployment.nat_mode {
                NatMode::Masquerade => {
                    batch.add(NfListObject::Rule(Rule {
                        family: NfFamily::INet,
                        table: Cow::Owned(self.config.table_name.clone()),
                        chain: Cow::Owned(nat_chain_name.clone()),
                        handle: None,
                        index: None,
                        comment: Some(Cow::Owned(format!("Masquerade on {}", iface))),
                        expr: Cow::Owned(vec![
                            Statement::Match(Match {
                                left: Expression::Named(NamedExpression::Meta(
                                    nftables::expr::Meta {
                                        key: nftables::expr::MetaKey::Oifname,
                                    },
                                )),
                                right: Expression::String(Cow::Owned(iface.clone())),
                                op: Operator::EQ,
                            }),
                            Statement::Masquerade(None),
                        ]),
                    }));
                }
                NatMode::Snat => {
                    // SNAT requires a specific IP - for now just log that it needs config
                    info!("SNAT mode configured but requires explicit IP address - skipping");
                }
                NatMode::None => {}
            }
        }

        info!("NAT rules added for {} mode", match self.deployment.nat_mode {
            NatMode::Masquerade => "masquerade",
            NatMode::Snat => "snat",
            NatMode::None => "none",
        });
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
        let mut banned = Vec::new();

        // Query each ban set on its own (`nft list set inet <table> <set>`) rather
        // than the whole ruleset: a full read-back would deserialize the DPI queue
        // rule, whose `"flags":"bypass"` form the nftables crate can't parse. A
        // scoped set listing has no rules. A missing set/table just yields nothing.
        for set_name in [self.config.set_v4.as_str(), self.config.set_v6.as_str()] {
            let args = [
                "list",
                "set",
                "inet",
                self.config.table_name.as_str(),
                set_name,
            ];
            let ruleset = match get_current_ruleset_with_args(DEFAULT_NFT, args.iter()) {
                Ok(r) => r,
                Err(_) => continue, // set or table not present yet — nothing banned
            };
            for obj in ruleset.objects.iter() {
                if let NfObject::ListObject(NfListObject::Set(set)) = obj {
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

    /// Add IP or CIDR entries to the inline-DPI allow sets.
    ///
    /// Entries (single IPs from the DB whitelist, or CIDR ranges such as the
    /// Cloudflare prefixes) are accepted in the dpi_inspect chain BEFORE the
    /// NFQUEUE, so those sources are never queued or inline-dropped by the engine.
    /// The sets are interval/CIDR-capable; `add element` is idempotent so this is
    /// safe to call on every startup and on each whitelist change. v6 entries
    /// (which contain ':') go to the v6 set; everything else to the v4 set.
    pub fn sync_dpi_allow(&self, entries: &[String]) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        info!(
            "Syncing {} entries to the inline-DPI allow sets",
            entries.len()
        );

        let mut batch = Batch::new();
        let mut added = 0usize;
        for entry in entries {
            // Only feed nft a literal IP or CIDR. A bare hostname (or any other
            // non-address token) makes nft attempt a DNS resolution; that fails
            // the whole ATOMIC batch — one bad whitelist row would otherwise take
            // the daemon down at startup. Validate and skip instead.
            if !is_ip_or_cidr(entry) {
                warn!(
                    "Skipping non-IP/CIDR inline-DPI allow entry {:?} (not an address)",
                    entry
                );
                continue;
            }
            let set_name = if entry.contains(':') {
                DPI_ALLOW_SET_V6
            } else {
                DPI_ALLOW_SET_V4
            };
            // A CIDR must be a `prefix` expression, NOT a bare "addr/len" string:
            // nft can't parse a slash-bearing string element and falls back to a
            // (failing) DNS lookup — "Could not resolve hostname" — which fails the
            // whole atomic batch. A single IP stays a plain string. is_ip_or_cidr
            // above guarantees the split parses.
            let elem_expr = match entry.split_once('/') {
                Some((addr, len)) => {
                    Expression::Named(NamedExpression::Prefix(nftables::expr::Prefix {
                        addr: Box::new(Expression::String(Cow::Owned(addr.to_string()))),
                        len: len.parse().unwrap_or(0),
                    }))
                }
                None => Expression::String(Cow::Owned(entry.clone())),
            };
            batch.add_cmd(NfCmd::Add(NfListObject::Element(Element {
                family: NfFamily::INet,
                table: Cow::Owned(self.config.table_name.clone()),
                name: Cow::Borrowed(set_name),
                elem: Cow::Owned(vec![elem_expr]),
            })));
            added += 1;
        }
        if added == 0 {
            return Ok(());
        }

        let ruleset = batch.to_nftables();
        apply_ruleset(&ruleset).context("Failed to sync inline-DPI allow set")?;
        Ok(())
    }

    /// Initialize outbound allowlist from config (for HostLite mode)
    fn init_outbound_allowlist(&self, batch: &mut Batch) {
        if self.deployment.outbound_allowlist.is_empty() {
            return;
        }

        info!(
            "Initializing outbound allowlist with {} entries",
            self.deployment.outbound_allowlist.len()
        );

        for addr_str in &self.deployment.outbound_allowlist {
            // Try to parse as IP address or CIDR
            if let Ok(ip) = addr_str.parse::<IpAddr>() {
                match ip {
                    IpAddr::V4(v4) => {
                        batch.add_cmd(NfCmd::Add(NfListObject::Element(Element {
                            family: NfFamily::INet,
                            table: Cow::Owned(self.config.table_name.clone()),
                            name: Cow::Borrowed("allowed_outbound_v4"),
                            elem: Cow::Owned(vec![Expression::String(Cow::Owned(v4.to_string()))]),
                        })));
                    }
                    IpAddr::V6(v6) => {
                        batch.add_cmd(NfCmd::Add(NfListObject::Element(Element {
                            family: NfFamily::INet,
                            table: Cow::Owned(self.config.table_name.clone()),
                            name: Cow::Borrowed("allowed_outbound_v6"),
                            elem: Cow::Owned(vec![Expression::String(Cow::Owned(v6.to_string()))]),
                        })));
                    }
                }
            } else if let Some((addr, len)) = addr_str.split_once('/') {
                // CIDR notation — emit a `prefix` expression, not a bare
                // "addr/len" string (nft can't parse the latter and tries a DNS
                // lookup, failing the whole batch). Skip if the parts don't parse.
                let (Ok(_), Ok(plen)) = (addr.parse::<IpAddr>(), len.parse::<u32>()) else {
                    warn!("Invalid CIDR in outbound allowlist: {}", addr_str);
                    continue;
                };
                batch.add_cmd(NfCmd::Add(NfListObject::Element(Element {
                    family: NfFamily::INet,
                    table: Cow::Owned(self.config.table_name.clone()),
                    name: if addr_str.contains(':') {
                        Cow::Borrowed("allowed_outbound_v6")
                    } else {
                        Cow::Borrowed("allowed_outbound_v4")
                    },
                    elem: Cow::Owned(vec![Expression::Named(NamedExpression::Prefix(
                        nftables::expr::Prefix {
                            addr: Box::new(Expression::String(Cow::Owned(addr.to_string()))),
                            len: plen,
                        },
                    ))]),
                })));
            } else {
                warn!("Invalid address in outbound allowlist: {}", addr_str);
            }
        }
    }

    /// Add an IP to the outbound allowlist (for HostLite mode)
    pub fn add_outbound_allow(&self, ip: &IpAddr) -> Result<()> {
        let mut batch = Batch::new();

        match ip {
            IpAddr::V4(v4) => {
                batch.add_cmd(NfCmd::Add(NfListObject::Element(Element {
                    family: NfFamily::INet,
                    table: Cow::Owned(self.config.table_name.clone()),
                    name: Cow::Borrowed("allowed_outbound_v4"),
                    elem: Cow::Owned(vec![Expression::String(Cow::Owned(v4.to_string()))]),
                })));
            }
            IpAddr::V6(v6) => {
                batch.add_cmd(NfCmd::Add(NfListObject::Element(Element {
                    family: NfFamily::INet,
                    table: Cow::Owned(self.config.table_name.clone()),
                    name: Cow::Borrowed("allowed_outbound_v6"),
                    elem: Cow::Owned(vec![Expression::String(Cow::Owned(v6.to_string()))]),
                })));
            }
        }

        let ruleset = batch.to_nftables();
        apply_ruleset(&ruleset).context("Failed to add to outbound allowlist")?;

        info!("Added {} to outbound allowlist", ip);
        Ok(())
    }

    /// Remove an IP from the outbound allowlist (for HostLite mode)
    pub fn remove_outbound_allow(&self, ip: &IpAddr) -> Result<()> {
        let mut batch = Batch::new();

        match ip {
            IpAddr::V4(v4) => {
                batch.add_cmd(NfCmd::Delete(NfListObject::Element(Element {
                    family: NfFamily::INet,
                    table: Cow::Owned(self.config.table_name.clone()),
                    name: Cow::Borrowed("allowed_outbound_v4"),
                    elem: Cow::Owned(vec![Expression::String(Cow::Owned(v4.to_string()))]),
                })));
            }
            IpAddr::V6(v6) => {
                batch.add_cmd(NfCmd::Delete(NfListObject::Element(Element {
                    family: NfFamily::INet,
                    table: Cow::Owned(self.config.table_name.clone()),
                    name: Cow::Borrowed("allowed_outbound_v6"),
                    elem: Cow::Owned(vec![Expression::String(Cow::Owned(v6.to_string()))]),
                })));
            }
        }

        let ruleset = batch.to_nftables();
        apply_ruleset(&ruleset).context("Failed to remove from outbound allowlist")?;

        info!("Removed {} from outbound allowlist", ip);
        Ok(())
    }

    /// Block outbound traffic to a specific destination (for HostLite mode)
    pub fn block_outbound(&self, ip: &IpAddr) -> Result<()> {
        // For blocking outbound, we remove from allowlist if in block mode
        // In log mode, this is a no-op as we don't block
        if self.deployment.output_action == crate::config::OutputAction::Block {
            self.remove_outbound_allow(ip)?;
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

        // NOTE: the per-flag rules (SYN/NULL/XMAS/FIN/UDP) were removed. As written
        // they matched only `meta l4proto tcp|udp` with NO flag/state filter, so each
        // logged EVERY packet — a kern.log/disk flood (the original crmonban incident).
        // Scan detection works off the single rate-limited new-connection rule below:
        // it logs each new connection's dest port, and the monitor bans an IP that
        // touches more than `threshold` distinct ports within the window.
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
                    left: Expression::Named(NamedExpression::Meta(nftables::expr::Meta { key: nftables::expr::MetaKey::L4proto })),
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
                    left: Expression::Named(NamedExpression::Meta(nftables::expr::Meta { key: nftables::expr::MetaKey::L4proto })),
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
                    left: Expression::Named(NamedExpression::Meta(nftables::expr::Meta { key: nftables::expr::MetaKey::L4proto })),
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
                    left: Expression::Named(NamedExpression::Meta(nftables::expr::Meta { key: nftables::expr::MetaKey::L4proto })),
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
                    left: Expression::Named(NamedExpression::Meta(nftables::expr::Meta { key: nftables::expr::MetaKey::L4proto })),
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
                // Match new connections (ct state new) — proper ct expression,
                // not a payload field (the payload form is invalid nft JSON).
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::CT(nftables::expr::CT {
                        key: Cow::Borrowed("state"),
                        family: None,
                        dir: None,
                    })),
                    right: Expression::String(Cow::Borrowed("new")),
                    op: Operator::EQ,
                }),
                // Hard rate cap BEFORE the log: this rule can never write more than
                // ~50 lines/sec to kern.log regardless of traffic, so it cannot fill
                // the disk. A real scanner trips the per-IP port threshold long before
                // this cap matters; legit traffic stays far under it.
                Statement::Limit(Limit {
                    rate: 50,
                    rate_unit: None,
                    per: Some(Cow::Borrowed("second")),
                    burst: Some(100),
                    burst_unit: None,
                    inv: None,
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

    /// Add the INPUT inline-DPI chain. Entry point (also used by `init_dpi`).
    fn add_dpi_rules(&self, batch: &mut Batch, config: &DpiConfig) {
        self.add_dpi_chain(batch, "dpi_inspect", NfHook::Input, config);
    }

    /// Add the inline-DPI NFQUEUE chain `chain_name` on `hook`.
    ///
    /// The chain sits at priority+5 — AFTER the `@blocked` drop rules (at
    /// `priority`) — so already-banned sources are dropped in-kernel and never
    /// reach the queue. Used for the INPUT chain always, and the FORWARD chain on
    /// gateway deployments.
    ///
    /// NOTE: on the forward hook this queues ALL transit TCP; on a gateway that is
    /// also a Docker/forwarding host, scope it by interface (`iifname`) so
    /// container traffic isn't funnelled to userspace — a follow-up.
    fn add_dpi_chain(&self, batch: &mut Batch, chain_name: &str, hook: NfHook, config: &DpiConfig) {
        info!(
            "Adding DPI NFQUEUE chain {} (queue {})",
            chain_name, config.queue_num
        );

        // Create a separate base chain for DPI processing on this hook.
        batch.add(NfListObject::Chain(Chain {
            family: NfFamily::INet,
            table: Cow::Owned(self.config.table_name.clone()),
            name: Cow::Owned(chain_name.to_string()),
            newname: None,
            handle: None,
            _type: Some(NfChainType::Filter),
            hook: Some(hook),
            prio: Some(self.config.priority + 5), // After block rules, before port scan
            dev: None,
            policy: Some(NfChainPolicy::Accept),
        }));

        // Whitelist short-circuit: accept whitelisted sources in THIS chain,
        // ABOVE the queue rule. `accept` ends this base chain for these packets,
        // so whitelisted traffic is never queued and therefore never inline-
        // dropped by the engine. The -100 chain's whitelist accept does NOT carry
        // over (accept is not terminal across base chains), so the short-circuit
        // must be repeated here. Populated from the DB whitelist via
        // sync_whitelist(); the sets are interval/CIDR-capable.
        batch.add(NfListObject::Rule(Rule {
            family: NfFamily::INet,
            table: Cow::Owned(self.config.table_name.clone()),
            chain: Cow::Owned(chain_name.to_string()),
            handle: None,
            index: None,
            comment: Some(Cow::Borrowed("Accept whitelisted IPv4 before DPI queue")),
            expr: Cow::Owned(vec![
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                        PayloadField {
                            protocol: Cow::Borrowed("ip"),
                            field: Cow::Borrowed("saddr"),
                        },
                    ))),
                    right: Expression::String(Cow::Owned(format!("@{}", DPI_ALLOW_SET_V4))),
                    op: Operator::IN,
                }),
                // Counter makes this path observable: how many packets were
                // short-circuited as whitelisted before ever reaching the queue.
                Statement::Counter(Counter::Anonymous(None)),
                Statement::Accept(None),
            ]),
        }));
        batch.add(NfListObject::Rule(Rule {
            family: NfFamily::INet,
            table: Cow::Owned(self.config.table_name.clone()),
            chain: Cow::Owned(chain_name.to_string()),
            handle: None,
            index: None,
            comment: Some(Cow::Borrowed("Accept whitelisted IPv6 before DPI queue")),
            expr: Cow::Owned(vec![
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                        PayloadField {
                            protocol: Cow::Borrowed("ip6"),
                            field: Cow::Borrowed("saddr"),
                        },
                    ))),
                    right: Expression::String(Cow::Owned(format!("@{}", DPI_ALLOW_SET_V6))),
                    op: Operator::IN,
                }),
                Statement::Counter(Counter::Anonymous(None)),
                Statement::Accept(None),
            ]),
        }));

        // Kernel fast-path: a flow the engine has already judged good (its ct mark
        // is set by the verdict round-trip below) bypasses the queue entirely from
        // here on — accepted in-kernel, never re-queued. This is the M3 flow cache
        // realized at kernel speed. Placed ABOVE the queue rule so it wins first.
        batch.add(NfListObject::Rule(Rule {
            family: NfFamily::INet,
            table: Cow::Owned(self.config.table_name.clone()),
            chain: Cow::Owned(chain_name.to_string()),
            handle: None,
            index: None,
            comment: Some(Cow::Borrowed("Bypass engine-marked-good flows in-kernel")),
            expr: Cow::Owned(vec![
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::CT(nftables::expr::CT {
                        key: Cow::Borrowed("mark"),
                        family: None,
                        dir: None,
                    })),
                    right: Expression::Number(DPI_GOOD_MARK),
                    op: Operator::EQ,
                }),
                // Counter = how many packets bypassed the queue in-kernel because
                // the engine had already marked the flow good (the fast-path hit
                // rate — the whole point of the ct-mark cache).
                Statement::Counter(Counter::Anonymous(None)),
                Statement::Accept(None),
            ]),
        }));

        // Queue the FIRST N packets of each TCP connection to userspace for DPI.
        //
        // First-N (`ct packets <= packets_per_conn`) is the primary volume
        // control: attacks are detectable in the opening packets (handshake, TLS
        // ClientHello, HTTP request line, exploit payload), so we inspect the
        // start of each flow and then let the rest pass IN-KERNEL. Once a flow
        // exceeds N packets the rule no longer matches, so established traffic is
        // accepted by the kernel WITHOUT re-queuing — no per-packet userspace
        // cost. (packets_per_conn == 0 disables the limit and queues all
        // new+established.)
        // meta l4proto { tcp, udp, icmp, icmpv6 } — the L4 protocols queued for DPI
        // (configurable via dpi.queue_l4protos; default tcp+udp+icmp+icmpv6 so UDP
        // (incl. QUIC/HTTP-3 on 443/udp) and ICMP (ping sweeps) are inspected, not
        // just TCP). One protocol renders as a bare string; several as an anonymous
        // set. This is a meta expression, NOT a payload field:
        // `{"payload":{"protocol":"meta",...}}` makes nft reject the whole ruleset
        // with "Unknown payload protocol 'meta'". It must be `{"meta":{"key":"l4proto"}}`.
        let protos: Vec<String> = if config.queue_l4protos.is_empty() {
            vec!["tcp".to_string()]
        } else {
            config.queue_l4protos.clone()
        };
        let l4proto_right = if protos.len() == 1 {
            Expression::String(Cow::Owned(protos[0].clone()))
        } else {
            Expression::Named(NamedExpression::Set(
                protos
                    .iter()
                    .map(|p| {
                        nftables::expr::SetItem::Element(Expression::String(Cow::Owned(p.clone())))
                    })
                    .collect(),
            ))
        };
        let mut dpi_expr = vec![
            Statement::Match(Match {
                left: Expression::Named(NamedExpression::Meta(nftables::expr::Meta {
                    key: nftables::expr::MetaKey::L4proto,
                })),
                right: l4proto_right,
                op: Operator::EQ,
            }),
            // ct state { new, established } as an anonymous SET. The comma-string
            // form ("new,established") is invalid nft JSON and would make the
            // whole rule fail to apply — it must be {"set":["new","established"]}.
            Statement::Match(Match {
                left: Expression::Named(NamedExpression::CT(nftables::expr::CT {
                    key: Cow::Borrowed("state"),
                    family: None,
                    dir: None,
                })),
                right: Expression::Named(NamedExpression::Set(vec![
                    nftables::expr::SetItem::Element(Expression::String(Cow::Borrowed("new"))),
                    nftables::expr::SetItem::Element(Expression::String(Cow::Borrowed(
                        "established",
                    ))),
                ])),
                op: Operator::EQ,
            }),
        ];
        if config.queue_until_decided {
            // Queue-until-decided: inspect every packet of a flow whose verdict is
            // not yet decided — i.e. its conntrack mark is still unset (0). Once
            // the engine marks the flow GOOD the bypass rule above accepts the
            // rest in-kernel; a flow that stays undecided keeps being inspected,
            // and a BAD flow keeps being dropped for its whole life. Unlike
            // first-N, the cutoff is the VERDICT, not a fixed packet count — so a
            // bad flow's later packets are never let through.
            dpi_expr.push(Statement::Match(Match {
                left: Expression::Named(NamedExpression::CT(nftables::expr::CT {
                    key: Cow::Borrowed("mark"),
                    family: None,
                    dir: None,
                })),
                right: Expression::Number(0),
                op: Operator::EQ,
            }));
        } else if config.packets_per_conn > 0 {
            // Legacy first-N: ct packets (ORIGINAL direction = inbound for a server
            // connection) <= N — only the first N inbound packets. Stops at a fixed
            // count regardless of verdict.
            dpi_expr.push(Statement::Match(Match {
                left: Expression::Named(NamedExpression::CT(nftables::expr::CT {
                    key: Cow::Borrowed("packets"),
                    family: None,
                    dir: Some(nftables::expr::CTDir::Original),
                })),
                right: Expression::Number(config.packets_per_conn as u32),
                op: Operator::LEQ,
            }));
        }
        // Queue to userspace with the `bypass` flag = FAIL-OPEN: the kernel
        // ACCEPTS (rather than drops) when there is no listener OR the queue is
        // full. Availability first — under overload, traffic passes UNINSPECTED
        // (monitor queue depth to detect saturation).
        // Counter BEFORE the queue verdict = how many packets were actually sent
        // to userspace for inspection (the first-N of each flow). Comparing this to
        // the bypass counter shows the inspect-vs-fast-path split.
        dpi_expr.push(Statement::Counter(Counter::Anonymous(None)));
        dpi_expr.push(Statement::Queue(Queue {
            num: Expression::Number(config.queue_num as u32),
            flags: Some(HashSet::from([QueueFlag::Bypass])),
        }));
        batch.add(NfListObject::Rule(Rule {
            family: NfFamily::INet,
            table: Cow::Owned(self.config.table_name.clone()),
            chain: Cow::Owned(chain_name.to_string()),
            handle: None,
            index: None,
            comment: Some(Cow::Borrowed("Queue undecided packets (tcp/udp/icmp/...) for DPI")),
            expr: Cow::Owned(dpi_expr),
        }));

        // Persist the engine's good verdict to conntrack. CRITICAL: this lives in a
        // SEPARATE base chain AFTER dpi_inspect, not as a later rule inside it. When
        // the engine returns NF_ACCEPT for a queued packet, the packet does NOT
        // resume at the next rule in the queuing chain — it proceeds to the next
        // base chain on the hook. A persist rule placed after the `queue` rule in
        // the same chain therefore never runs (verified on a live kernel: the GOOD
        // skb-mark was present in a later base chain, but a same-chain persist rule
        // counted 0). A dedicated base chain at priority+6 runs on the accepted
        // packet and copies its good packet-mark to the connection's ct mark, so the
        // bypass rule in dpi_inspect short-circuits every later packet of the flow.
        let persist_chain = format!("{}_persist", chain_name);
        batch.add(NfListObject::Chain(Chain {
            family: NfFamily::INet,
            table: Cow::Owned(self.config.table_name.clone()),
            name: Cow::Owned(persist_chain.clone()),
            newname: None,
            handle: None,
            _type: Some(NfChainType::Filter),
            hook: Some(hook),
            prio: Some(self.config.priority + 6),
            dev: None,
            policy: Some(NfChainPolicy::Accept),
        }));
        batch.add(NfListObject::Rule(Rule {
            family: NfFamily::INet,
            table: Cow::Owned(self.config.table_name.clone()),
            chain: Cow::Owned(persist_chain),
            handle: None,
            index: None,
            comment: Some(Cow::Borrowed("Persist good packet-mark to ct mark")),
            expr: Cow::Owned(vec![
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Meta(nftables::expr::Meta {
                        key: nftables::expr::MetaKey::Mark,
                    })),
                    right: Expression::Number(DPI_GOOD_MARK),
                    op: Operator::EQ,
                }),
                // Counter = how many good-verdict packets returned from userspace
                // and persisted their mark to conntrack (i.e. flows newly promoted
                // to the in-kernel fast-path).
                Statement::Counter(Counter::Anonymous(None)),
                Statement::Mangle(nftables::stmt::Mangle {
                    key: Expression::Named(NamedExpression::CT(nftables::expr::CT {
                        key: Cow::Borrowed("mark"),
                        family: None,
                        dir: None,
                    })),
                    value: Expression::Number(DPI_GOOD_MARK),
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
                        left: Expression::Named(NamedExpression::Meta(nftables::expr::Meta { key: nftables::expr::MetaKey::L4proto })),
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

    /// Add port-based firewall rules (UFW-like functionality)
    fn add_port_rules(&self, batch: &mut Batch, config: &PortRulesConfig) {
        info!("Adding port-based firewall rules (default policy: {})", config.default_input_policy);

        // Create a separate chain for port filtering with higher priority (runs after blocklist)
        batch.add(NfListObject::Chain(Chain {
            family: NfFamily::INet,
            table: Cow::Owned(self.config.table_name.clone()),
            name: Cow::Borrowed("port_filter"),
            newname: None,
            handle: None,
            _type: Some(NfChainType::Filter),
            hook: Some(NfHook::Input),
            prio: Some(self.config.priority + 50), // After blocklist but with room for other chains
            dev: None,
            policy: Some(NfChainPolicy::Drop), // Default deny - rules must explicitly allow
        }));

        // Allow loopback traffic
        if config.allow_loopback {
            batch.add(NfListObject::Rule(Rule {
                family: NfFamily::INet,
                table: Cow::Owned(self.config.table_name.clone()),
                chain: Cow::Borrowed("port_filter"),
                handle: None,
                index: None,
                comment: Some(Cow::Borrowed("Allow loopback")),
                expr: Cow::Owned(vec![
                    Statement::Match(Match {
                        left: Expression::Named(NamedExpression::Meta(nftables::expr::Meta { key: nftables::expr::MetaKey::Iifname })),
                        right: Expression::String(Cow::Borrowed("lo")),
                        op: Operator::EQ,
                    }),
                    Statement::Accept(None),
                ]),
            }));
        }

        // Allow established/related connections (stateful)
        if config.allow_established {
            batch.add(NfListObject::Rule(Rule {
                family: NfFamily::INet,
                table: Cow::Owned(self.config.table_name.clone()),
                chain: Cow::Borrowed("port_filter"),
                handle: None,
                index: None,
                comment: Some(Cow::Borrowed("Allow established/related")),
                expr: Cow::Owned(vec![
                    // ct state { established, related } — proper ct expression and
                    // an anonymous SET (the comma-string form is invalid nft JSON).
                    Statement::Match(Match {
                        left: Expression::Named(NamedExpression::CT(nftables::expr::CT {
                            key: Cow::Borrowed("state"),
                            family: None,
                            dir: None,
                        })),
                        right: Expression::Named(NamedExpression::Set(vec![
                            nftables::expr::SetItem::Element(Expression::String(Cow::Borrowed(
                                "established",
                            ))),
                            nftables::expr::SetItem::Element(Expression::String(Cow::Borrowed(
                                "related",
                            ))),
                        ])),
                        op: Operator::EQ,
                    }),
                    Statement::Accept(None),
                ]),
            }));
        }

        // Allow ICMP (ping)
        if config.allow_icmp {
            // IPv4 ICMP
            batch.add(NfListObject::Rule(Rule {
                family: NfFamily::INet,
                table: Cow::Owned(self.config.table_name.clone()),
                chain: Cow::Borrowed("port_filter"),
                handle: None,
                index: None,
                comment: Some(Cow::Borrowed("Allow ICMP (ping)")),
                expr: Cow::Owned(vec![
                    Statement::Match(Match {
                        left: Expression::Named(NamedExpression::Meta(nftables::expr::Meta { key: nftables::expr::MetaKey::L4proto })),
                        right: Expression::String(Cow::Borrowed("icmp")),
                        op: Operator::EQ,
                    }),
                    Statement::Accept(None),
                ]),
            }));
            // IPv6 ICMPv6
            batch.add(NfListObject::Rule(Rule {
                family: NfFamily::INet,
                table: Cow::Owned(self.config.table_name.clone()),
                chain: Cow::Borrowed("port_filter"),
                handle: None,
                index: None,
                comment: Some(Cow::Borrowed("Allow ICMPv6")),
                expr: Cow::Owned(vec![
                    Statement::Match(Match {
                        left: Expression::Named(NamedExpression::Meta(nftables::expr::Meta { key: nftables::expr::MetaKey::L4proto })),
                        right: Expression::String(Cow::Borrowed("ipv6-icmp")),
                        op: Operator::EQ,
                    }),
                    Statement::Accept(None),
                ]),
            }));
        }

        // Sort rules by priority (lower number = earlier evaluation)
        let mut sorted_rules: Vec<&PortRule> = config.rules.iter().filter(|r| r.enabled).collect();
        sorted_rules.sort_by_key(|r| r.priority);

        // Add user-defined port rules
        for rule in sorted_rules {
            if rule.direction == "in" || rule.direction == "both" {
                self.add_single_port_rule(batch, rule, "port_filter");
            }
        }

        // Log denied packets before dropping (optional)
        batch.add(NfListObject::Rule(Rule {
            family: NfFamily::INet,
            table: Cow::Owned(self.config.table_name.clone()),
            chain: Cow::Borrowed("port_filter"),
            handle: None,
            index: None,
            comment: Some(Cow::Borrowed("Log denied packets")),
            expr: Cow::Owned(vec![
                Statement::Log(Some(Log {
                    prefix: Some(Cow::Borrowed("[crmonban-denied] ")),
                    group: None,
                    snaplen: None,
                    queue_threshold: None,
                    level: Some(LogLevel::Warn),
                    flags: None,
                })),
            ]),
        }));

        // Default policy is DROP (set in chain policy above)
        info!("Port filter rules added ({} user rules)", config.rules.len());
    }

    /// Add a single port rule to the batch
    fn add_single_port_rule<'a>(&self, batch: &mut Batch<'a>, rule: &PortRule, chain: &'a str) {
        let protocol = rule.protocol.as_str();
        let port_str = &rule.port;

        // Build match expressions
        let mut exprs: Vec<Statement> = Vec::new();

        // Protocol match (unless "any")
        if protocol != "any" {
            exprs.push(Statement::Match(Match {
                left: Expression::Named(NamedExpression::Meta(nftables::expr::Meta { key: nftables::expr::MetaKey::L4proto })),
                right: Expression::String(Cow::Owned(protocol.to_string())),
                op: Operator::EQ,
            }));
        }

        // Port match
        if port_str.contains('-') {
            // Port range - use set with range
            let parts: Vec<&str> = port_str.split('-').collect();
            if parts.len() == 2 {
                if let (Ok(start), Ok(end)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
                    exprs.push(Statement::Match(Match {
                        left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                            PayloadField {
                                protocol: Cow::Owned(protocol.to_string()),
                                field: Cow::Borrowed("dport"),
                            },
                        ))),
                        right: Expression::Range(Box::new(Range {
                            range: [
                                Expression::Number(start),
                                Expression::Number(end),
                            ],
                        })),
                        op: Operator::EQ,
                    }));
                }
            }
        } else {
            // Single port or comma-separated
            if let Ok(port) = port_str.parse::<u32>() {
                exprs.push(Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                        PayloadField {
                            protocol: Cow::Owned(protocol.to_string()),
                            field: Cow::Borrowed("dport"),
                        },
                    ))),
                    right: Expression::Number(port),
                    op: Operator::EQ,
                }));
            }
        }

        // Source IP match (if specified)
        if let Some(ref from) = rule.from {
            if !from.is_empty() {
                exprs.push(Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                        PayloadField {
                            protocol: Cow::Borrowed("ip"),
                            field: Cow::Borrowed("saddr"),
                        },
                    ))),
                    right: Expression::String(Cow::Owned(from.clone())),
                    op: Operator::EQ,
                }));
            }
        }

        // Action
        match rule.action {
            PortAction::Allow => {
                exprs.push(Statement::Accept(None));
            }
            PortAction::Deny => {
                exprs.push(Statement::Drop(None));
            }
            PortAction::Reject => {
                exprs.push(Statement::Reject(None));
            }
            PortAction::Log => {
                exprs.push(Statement::Log(Some(Log {
                    prefix: Some(Cow::Owned(format!("[crmonban-port-{}] ", port_str))),
                    group: None,
                    snaplen: None,
                    queue_threshold: None,
                    level: Some(LogLevel::Info),
                    flags: None,
                })));
            }
        }

        let comment = if rule.comment.is_empty() {
            format!("{} {} port {}", rule.action, protocol, port_str)
        } else {
            rule.comment.clone()
        };

        batch.add(NfListObject::Rule(Rule {
            family: NfFamily::INet,
            table: Cow::Owned(self.config.table_name.clone()),
            chain: Cow::Borrowed(chain),
            handle: None,
            index: None,
            comment: Some(Cow::Owned(comment)),
            expr: Cow::Owned(exprs),
        }));
    }

    /// Initialize port rules (can be called separately to add rules to existing table)
    pub fn init_port_rules(&self, config: &PortRulesConfig) -> Result<()> {
        if !config.enabled {
            debug!("Port rules are disabled");
            return Ok(());
        }

        if !self.table_exists()? {
            return Err(anyhow::anyhow!(
                "Table {} does not exist. Initialize firewall first.",
                self.config.table_name
            ));
        }

        let mut batch = Batch::new();
        self.add_port_rules(&mut batch, config);

        let ruleset = batch.to_nftables();
        apply_ruleset(&ruleset).context("Failed to apply port rules")?;

        info!("Port rules initialized");
        Ok(())
    }

    /// Add a single port rule dynamically (runtime)
    pub fn add_port_rule(&self, rule: &PortRule) -> Result<()> {
        if !self.table_exists()? {
            return Err(anyhow::anyhow!(
                "Table {} does not exist. Initialize firewall first.",
                self.config.table_name
            ));
        }

        let mut batch = Batch::new();
        self.add_single_port_rule(&mut batch, rule, "port_filter");

        let ruleset = batch.to_nftables();
        apply_ruleset(&ruleset).context("Failed to add port rule")?;

        info!("Added port rule: {} {} port {}", rule.action, rule.protocol, rule.port);
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
