use anyhow::{Context, Result};
use nftables::{
    batch::Batch,
    expr::{Elem, Expression, NamedExpression, Payload, PayloadField},
    helper::{apply_ruleset, get_current_ruleset},
    schema::{
        Chain, Element, FlushObject, NfCmd, NfListObject, NfObject, Rule, Set, SetFlag,
        SetType, SetTypeValue, Table,
    },
    stmt::{Match, Operator, Statement},
    types::{NfChainPolicy, NfChainType, NfFamily, NfHook},
};
use std::borrow::Cow;
use std::collections::HashSet;
use std::net::IpAddr;
use tracing::{debug, info, warn};

use crate::config::NftablesConfig;

/// Firewall manager for nftables operations
pub struct Firewall {
    config: NftablesConfig,
}

impl Firewall {
    /// Create a new firewall manager
    pub fn new(config: NftablesConfig) -> Self {
        Self { config }
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
