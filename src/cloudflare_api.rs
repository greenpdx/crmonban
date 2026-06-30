//! Cloudflare-edge enforcement (M1).
//!
//! Mirrors crmonban's active-ban set into a Cloudflare **account IP List** so that
//! CF-proxied attacks — whose real client IP only exists at the edge (the encrypted
//! `CF-Connecting-IP`), never in an origin packet — are blocked at Cloudflare too,
//! not just by the kernel `@blocked` set. One blocklist, both attack paths.
//!
//! Uses **IP Lists + one WAF rule** (`ip.src in $list`), so runtime is bulk
//! add/remove of list *items*, never per-IP rule churn. The DB ban table is the
//! source of truth; the reconciler makes the CF list equal it (add missing, remove
//! expired — CF list items have no native TTL, unlike nft timeout sets).

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::IpAddr;
use tracing::{info, warn};

use crate::config::CloudflareConfig;

const API_BASE: &str = "https://api.cloudflare.com/client/v4";

/// Load the API token from the configured file (preferred) or inline value.
pub fn load_token(cfg: &CloudflareConfig) -> Result<String> {
    if !cfg.api_token_file.is_empty() {
        let t = std::fs::read_to_string(&cfg.api_token_file)
            .with_context(|| format!("reading cloudflare.api_token_file {}", cfg.api_token_file))?;
        let t = t.trim().to_string();
        if t.is_empty() {
            return Err(anyhow!("cloudflare api_token_file {} is empty", cfg.api_token_file));
        }
        return Ok(t);
    }
    if !cfg.api_token.is_empty() {
        return Ok(cfg.api_token.clone());
    }
    Err(anyhow!("cloudflare enabled but no api_token_file or api_token set"))
}

pub struct CloudflareApi {
    client: reqwest::Client,
    token: String,
    account_id: String,
}

#[derive(Deserialize)]
struct Envelope<T> {
    success: bool,
    #[serde(default)]
    errors: Vec<ApiError>,
    result: Option<T>,
    #[serde(default)]
    result_info: Option<ResultInfo>,
}

#[derive(Deserialize)]
struct ApiError {
    code: i64,
    message: String,
}

#[derive(Deserialize, Default)]
struct ResultInfo {
    cursors: Option<Cursors>,
}

#[derive(Deserialize)]
struct Cursors {
    after: Option<String>,
}

#[derive(Deserialize)]
struct ListMeta {
    id: String,
    name: String,
}

#[derive(Deserialize)]
struct ListItem {
    id: String,
    ip: Option<String>,
}

#[derive(Deserialize)]
struct Zone {
    id: String,
    #[serde(default)]
    name: String,
}

#[derive(Deserialize)]
struct AccessRule {
    id: String,
    configuration: AccessRuleConfig,
    #[serde(default)]
    notes: Option<String>,
}

#[derive(Deserialize)]
struct AccessRuleConfig {
    #[serde(default)]
    target: String,
    #[serde(default)]
    value: String,
}

/// What one reconcile pass did.
#[derive(Debug, Default)]
pub struct ReconcileReport {
    pub list_id: String,
    pub edge_total: usize,
    pub added: usize,
    pub removed: usize,
}

impl CloudflareApi {
    pub fn new(token: String, account_id: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            token,
            account_id,
        }
    }

    fn err_str(errors: &[ApiError]) -> String {
        errors
            .iter()
            .map(|e| format!("{}:{}", e.code, e.message))
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Resolve the list ID: use the configured one if set, else find by name, else
    /// create it. Returns the resolved ID.
    pub async fn ensure_list(&self, configured_id: &str, name: &str) -> Result<String> {
        if !configured_id.is_empty() {
            return Ok(configured_id.to_string());
        }
        // find by name
        let url = format!("{}/accounts/{}/rules/lists", API_BASE, self.account_id);
        let env: Envelope<Vec<ListMeta>> = self
            .client
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await?
            .json()
            .await
            .context("parse rules/lists")?;
        if !env.success {
            return Err(anyhow!("CF list lookup failed: {}", Self::err_str(&env.errors)));
        }
        if let Some(found) = env
            .result
            .unwrap_or_default()
            .into_iter()
            .find(|l| l.name == name)
        {
            info!("cloudflare: using existing IP list '{}' (id {})", name, found.id);
            return Ok(found.id);
        }
        // create
        let body = serde_json::json!({
            "name": name,
            "kind": "ip",
            "description": "crmonban active bans (managed)"
        });
        let env: Envelope<ListMeta> = self
            .client
            .post(&url)
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await?
            .json()
            .await
            .context("parse create-list")?;
        if !env.success {
            return Err(anyhow!("CF list create failed: {}", Self::err_str(&env.errors)));
        }
        let id = env.result.ok_or_else(|| anyhow!("CF create-list: no result"))?.id;
        info!(
            "cloudflare: created IP list '{}' (id {}) — pin it in config as cloudflare.list_id",
            name, id
        );
        Ok(id)
    }

    /// Fetch every item in the list, as ip -> item_id (paginated).
    pub async fn list_items(&self, list_id: &str) -> Result<HashMap<String, String>> {
        let mut out = HashMap::new();
        let mut cursor: Option<String> = None;
        loop {
            let mut url = format!(
                "{}/accounts/{}/rules/lists/{}/items?per_page=1000",
                API_BASE, self.account_id, list_id
            );
            if let Some(c) = &cursor {
                url.push_str(&format!("&cursor={}", c));
            }
            let env: Envelope<Vec<ListItem>> = self
                .client
                .get(&url)
                .bearer_auth(&self.token)
                .send()
                .await?
                .json()
                .await
                .context("parse list items")?;
            if !env.success {
                return Err(anyhow!("CF list-items failed: {}", Self::err_str(&env.errors)));
            }
            for item in env.result.unwrap_or_default() {
                if let Some(ip) = item.ip {
                    out.insert(ip, item.id);
                }
            }
            cursor = env
                .result_info
                .and_then(|ri| ri.cursors)
                .and_then(|c| c.after);
            if cursor.is_none() {
                break;
            }
        }
        Ok(out)
    }

    /// Bulk-add IPs (async on CF's side; converges by the next reconcile).
    pub async fn add_items(&self, list_id: &str, ips: &[IpAddr]) -> Result<()> {
        if ips.is_empty() {
            return Ok(());
        }
        let body: Vec<serde_json::Value> = ips
            .iter()
            .map(|ip| serde_json::json!({ "ip": ip.to_string(), "comment": "crmonban" }))
            .collect();
        let url = format!(
            "{}/accounts/{}/rules/lists/{}/items",
            API_BASE, self.account_id, list_id
        );
        let env: Envelope<serde_json::Value> = self
            .client
            .post(&url)
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await?
            .json()
            .await
            .context("parse add-items")?;
        if !env.success {
            return Err(anyhow!("CF add-items failed: {}", Self::err_str(&env.errors)));
        }
        Ok(())
    }

    /// Bulk-remove list items by item ID.
    pub async fn remove_items(&self, list_id: &str, item_ids: &[String]) -> Result<()> {
        if item_ids.is_empty() {
            return Ok(());
        }
        let body = serde_json::json!({
            "items": item_ids.iter().map(|id| serde_json::json!({"id": id})).collect::<Vec<_>>()
        });
        let url = format!(
            "{}/accounts/{}/rules/lists/{}/items",
            API_BASE, self.account_id, list_id
        );
        let env: Envelope<serde_json::Value> = self
            .client
            .delete(&url)
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await?
            .json()
            .await
            .context("parse remove-items")?;
        if !env.success {
            return Err(anyhow!("CF remove-items failed: {}", Self::err_str(&env.errors)));
        }
        Ok(())
    }

    /// Make the CF list equal `active` (the current active-ban IPs). Adds the ones
    /// CF is missing, removes the ones no longer banned. Idempotent.
    pub async fn reconcile(
        &self,
        configured_list_id: &str,
        list_name: &str,
        active: &[IpAddr],
    ) -> Result<ReconcileReport> {
        let list_id = self.ensure_list(configured_list_id, list_name).await?;
        let edge = self.list_items(&list_id).await?;

        let active_set: std::collections::HashSet<String> =
            active.iter().map(|ip| ip.to_string()).collect();

        let to_add: Vec<IpAddr> = active
            .iter()
            .filter(|ip| !edge.contains_key(&ip.to_string()))
            .copied()
            .collect();
        let to_remove: Vec<String> = edge
            .iter()
            .filter(|(ip, _)| !active_set.contains(*ip))
            .map(|(_, id)| id.clone())
            .collect();

        let report = ReconcileReport {
            list_id: list_id.clone(),
            // Post-reconcile total: what's on the edge now, plus what we're about
            // to add, minus what we're about to remove. (to_remove ⊆ edge, so the
            // subtraction can't underflow.) Reporting edge.len() alone logged the
            // PRE-reconcile count.
            edge_total: edge.len() + to_add.len() - to_remove.len(),
            added: to_add.len(),
            removed: to_remove.len(),
        };

        if !to_add.is_empty() {
            self.add_items(&list_id, &to_add).await?;
        }
        if !to_remove.is_empty() {
            self.remove_items(&list_id, &to_remove).await?;
        }
        Ok(report)
    }

    // ---- Zone-level IP Access Rules mode (needs zone Firewall Services perm) ----

    /// Zone IDs the token can manage.
    pub async fn list_zone_ids(&self) -> Result<Vec<String>> {
        Ok(self.list_zones().await?.into_iter().map(|(id, _)| id).collect())
    }

    /// Zone (id, name) pairs accessible to the token.
    pub async fn list_zones(&self) -> Result<Vec<(String, String)>> {
        let mut out = Vec::new();
        let mut page = 1u32;
        loop {
            let url = format!("{}/zones?per_page=50&page={}", API_BASE, page);
            let env: Envelope<Vec<Zone>> = self
                .client
                .get(&url)
                .bearer_auth(&self.token)
                .send()
                .await?
                .json()
                .await
                .context("parse zones")?;
            if !env.success {
                return Err(anyhow!("CF zones failed: {}", Self::err_str(&env.errors)));
            }
            let batch = env.result.unwrap_or_default();
            let n = batch.len();
            out.extend(batch.into_iter().map(|z| (z.id, z.name)));
            if n < 50 || page > 50 {
                break;
            }
            page += 1;
        }
        Ok(out)
    }

    /// Our managed block rules in a zone (notes contain "crmonban"): ip -> rule_id.
    pub async fn zone_block_rules(&self, zone_id: &str) -> Result<HashMap<String, String>> {
        let mut out = HashMap::new();
        let mut page = 1u32;
        loop {
            let url = format!(
                "{}/zones/{}/firewall/access_rules/rules?per_page=100&page={}&mode=block",
                API_BASE, zone_id, page
            );
            let env: Envelope<Vec<AccessRule>> = self
                .client
                .get(&url)
                .bearer_auth(&self.token)
                .send()
                .await?
                .json()
                .await
                .context("parse access rules")?;
            if !env.success {
                return Err(anyhow!(
                    "CF access-rules list failed: {}",
                    Self::err_str(&env.errors)
                ));
            }
            let batch = env.result.unwrap_or_default();
            let n = batch.len();
            for r in batch {
                let ours = r
                    .notes
                    .as_deref()
                    .map(|s| s.contains("crmonban"))
                    .unwrap_or(false);
                if ours && r.configuration.target == "ip" {
                    out.insert(r.configuration.value, r.id);
                }
            }
            if n < 100 || page > 100 {
                break;
            }
            page += 1;
        }
        Ok(out)
    }

    async fn add_zone_block(&self, zone_id: &str, ip: IpAddr) -> Result<()> {
        let body = serde_json::json!({
            "mode": "block",
            "configuration": { "target": "ip", "value": ip.to_string() },
            "notes": "crmonban"
        });
        let url = format!(
            "{}/zones/{}/firewall/access_rules/rules",
            API_BASE, zone_id
        );
        let env: Envelope<serde_json::Value> = self
            .client
            .post(&url)
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await?
            .json()
            .await
            .context("parse add access rule")?;
        if !env.success {
            let msg = Self::err_str(&env.errors);
            // a rule for this IP already existing is fine (idempotent)
            if msg.contains("already") || msg.contains("duplicate") || msg.contains("identical") {
                return Ok(());
            }
            return Err(anyhow!("CF add access-rule failed: {}", msg));
        }
        Ok(())
    }

    async fn remove_zone_rule(&self, zone_id: &str, rule_id: &str) -> Result<()> {
        let url = format!(
            "{}/zones/{}/firewall/access_rules/rules/{}",
            API_BASE, zone_id, rule_id
        );
        let env: Envelope<serde_json::Value> = self
            .client
            .delete(&url)
            .bearer_auth(&self.token)
            .send()
            .await?
            .json()
            .await
            .context("parse delete access rule")?;
        if !env.success {
            return Err(anyhow!(
                "CF delete access-rule failed: {}",
                Self::err_str(&env.errors)
            ));
        }
        Ok(())
    }

    /// Make each zone's crmonban-managed block rules equal `active`. Zones empty =
    /// every zone the token can manage.
    pub async fn reconcile_access_rules(
        &self,
        zones: &[String],
        active: &[IpAddr],
    ) -> Result<ReconcileReport> {
        let zone_ids = if zones.is_empty() {
            self.list_zone_ids().await?
        } else {
            zones.to_vec()
        };
        let active_set: std::collections::HashSet<String> =
            active.iter().map(|ip| ip.to_string()).collect();
        let mut report = ReconcileReport {
            list_id: format!("{} zone(s)", zone_ids.len()),
            ..Default::default()
        };
        for zid in &zone_ids {
            let existing = self.zone_block_rules(zid).await?;
            report.edge_total += existing.len();
            for ip in active.iter().filter(|ip| !existing.contains_key(&ip.to_string())) {
                self.add_zone_block(zid, *ip).await?;
                report.added += 1;
            }
            for (_, rid) in existing.iter().filter(|(ip, _)| !active_set.contains(*ip)) {
                self.remove_zone_rule(zid, rid).await?;
                report.removed += 1;
            }
        }
        // edge_total accumulated the PRE-reconcile rule count across all zones; fold
        // in the deltas so it reports the POST-reconcile total. (removed ⊆ existing,
        // so this can't underflow.)
        report.edge_total = report.edge_total + report.added - report.removed;
        Ok(report)
    }
}

/// Read-only edge state for `status`: (IPs blocked at the edge, zones covered).
/// For access_rules it counts a representative zone (the reconciler keeps every zone
/// equal); for list mode it counts the list. Returns Ok(None) when disabled.
pub async fn edge_status(cfg: &CloudflareConfig) -> Result<Option<(usize, usize)>> {
    if !cfg.enabled {
        return Ok(None);
    }
    let token = load_token(cfg)?;
    let api = CloudflareApi::new(token, cfg.account_id.clone());
    if cfg.mode == "access_rules" {
        let zones = if cfg.zones.is_empty() {
            api.list_zone_ids().await?
        } else {
            cfg.zones.clone()
        };
        let ips = match zones.first() {
            Some(z) => api.zone_block_rules(z).await?.len(),
            None => 0,
        };
        Ok(Some((ips, zones.len())))
    } else {
        let list_id = api.ensure_list(&cfg.list_id, &cfg.list_name).await?;
        let ips = api.list_items(&list_id).await?.len();
        Ok(Some((ips, 1)))
    }
}

/// List the IPs currently blocked at the Cloudflare edge.
///
/// access_rules mode: one `(zone_label, sorted_ips)` entry per zone (zone name
/// when known, else id). list mode: a single `(list_name, sorted_ips)` entry.
/// Only crmonban-managed block rules are returned (notes contain "crmonban").
pub async fn edge_list(cfg: &CloudflareConfig) -> Result<Vec<(String, Vec<String>)>> {
    if !cfg.enabled {
        return Ok(Vec::new());
    }
    let token = load_token(cfg)?;
    let api = CloudflareApi::new(token, cfg.account_id.clone());
    let mut out = Vec::new();
    if cfg.mode == "access_rules" {
        // Prefer (id, name) pairs; fall back to configured ids (label == id).
        let zones: Vec<(String, String)> = if cfg.zones.is_empty() {
            api.list_zones().await?
        } else {
            cfg.zones.iter().map(|z| (z.clone(), z.clone())).collect()
        };
        for (zid, zname) in zones {
            let mut ips: Vec<String> = api.zone_block_rules(&zid).await?.into_keys().collect();
            ips.sort_by_key(|s| s.parse::<IpAddr>().ok());
            let label = if zname.is_empty() { zid } else { zname };
            out.push((label, ips));
        }
    } else {
        let list_id = api.ensure_list(&cfg.list_id, &cfg.list_name).await?;
        let mut ips: Vec<String> = api.list_items(&list_id).await?.into_keys().collect();
        ips.sort_by_key(|s| s.parse::<IpAddr>().ok());
        out.push((cfg.list_name.clone(), ips));
    }
    Ok(out)
}

/// Run a single reconcile pass from config + the active-ban IP list. Returns Ok(None)
/// when Cloudflare enforcement is disabled (so callers can no-op cleanly).
pub async fn reconcile_once(
    cfg: &CloudflareConfig,
    active: &[IpAddr],
) -> Result<Option<ReconcileReport>> {
    if !cfg.enabled {
        return Ok(None);
    }
    if cfg.mode != "access_rules" && cfg.account_id.is_empty() {
        return Err(anyhow!("cloudflare.enabled (list mode) but account_id is empty"));
    }
    let token = load_token(cfg)?;
    let api = CloudflareApi::new(token, cfg.account_id.clone());
    let report = if cfg.mode == "access_rules" {
        api.reconcile_access_rules(&cfg.zones, active).await?
    } else {
        api.reconcile(&cfg.list_id, &cfg.list_name, active).await?
    };
    if report.added > 0 || report.removed > 0 {
        info!(
            "cloudflare reconcile: list {} now {} IPs (+{} -{})",
            report.list_id, report.edge_total, report.added, report.removed
        );
    } else {
        warn!(
            "cloudflare reconcile: list {} in sync ({} IPs)",
            report.list_id, report.edge_total
        );
    }
    Ok(Some(report))
}
