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
            edge_total: edge.len(),
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
    if cfg.account_id.is_empty() {
        return Err(anyhow!("cloudflare.enabled but account_id is empty"));
    }
    let token = load_token(cfg)?;
    let api = CloudflareApi::new(token, cfg.account_id.clone());
    let report = api
        .reconcile(&cfg.list_id, &cfg.list_name, active)
        .await?;
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
