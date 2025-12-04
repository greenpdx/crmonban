use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::models::{
    ActivityAction, ActivityLog, AttackEvent, AttackEventType, AttackStats, AttackerIntel, Ban,
    BanSource, WhitelistEntry,
};

/// Thread-safe database wrapper
#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl Database {
    /// Open or create database at the given path
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        // Ensure parent directory exists
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(&path)
            .with_context(|| format!("Failed to open database: {}", path.as_ref().display()))?;

        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };

        db.init_schema()?;
        Ok(db)
    }

    /// Open an in-memory database (for testing)
    pub fn open_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        db.init_schema()?;
        Ok(db)
    }

    /// Initialize database schema
    fn init_schema(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();

        conn.execute_batch(
            r#"
            -- Bans table
            CREATE TABLE IF NOT EXISTS bans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL UNIQUE,
                reason TEXT NOT NULL,
                source TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT,
                ban_count INTEGER DEFAULT 1
            );
            CREATE INDEX IF NOT EXISTS idx_bans_ip ON bans(ip);
            CREATE INDEX IF NOT EXISTS idx_bans_expires ON bans(expires_at);

            -- Attack events table
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                service TEXT NOT NULL,
                event_type TEXT NOT NULL,
                details TEXT,
                log_line TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip);
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_service ON events(service);

            -- Attacker intelligence table
            CREATE TABLE IF NOT EXISTS intel (
                ip TEXT PRIMARY KEY,
                gathered_at TEXT,
                country TEXT,
                country_code TEXT,
                city TEXT,
                region TEXT,
                latitude REAL,
                longitude REAL,
                timezone TEXT,
                asn INTEGER,
                as_org TEXT,
                isp TEXT,
                reverse_dns TEXT,
                whois_org TEXT,
                whois_registrar TEXT,
                whois_abuse_contact TEXT,
                whois_raw TEXT,
                is_tor_exit INTEGER,
                is_vpn INTEGER,
                is_proxy INTEGER,
                is_hosting INTEGER,
                threat_score INTEGER,
                open_ports TEXT,
                hostnames TEXT,
                shodan_tags TEXT
            );

            -- Whitelist table
            CREATE TABLE IF NOT EXISTS whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL UNIQUE,
                comment TEXT,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_whitelist_ip ON whitelist(ip);

            -- Activity log table
            CREATE TABLE IF NOT EXISTS activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                ip TEXT,
                details TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_activity_timestamp ON activity_log(timestamp);
            "#,
        )?;

        Ok(())
    }

    // ==================== Ban Operations ====================

    /// Add a new ban or update existing
    pub fn add_ban(&self, ban: &Ban) -> Result<i64> {
        let conn = self.conn.lock().unwrap();

        // Check if already banned
        let existing: Option<i64> = conn
            .query_row(
                "SELECT id FROM bans WHERE ip = ?",
                [ban.ip.to_string()],
                |row| row.get(0),
            )
            .optional()?;

        if let Some(id) = existing {
            // Update existing ban
            conn.execute(
                "UPDATE bans SET reason = ?, source = ?, expires_at = ?, ban_count = ban_count + 1 WHERE id = ?",
                params![
                    ban.reason,
                    ban.source.to_string(),
                    ban.expires_at.map(|t| t.to_rfc3339()),
                    id
                ],
            )?;
            Ok(id)
        } else {
            // Insert new ban
            conn.execute(
                "INSERT INTO bans (ip, reason, source, created_at, expires_at, ban_count) VALUES (?, ?, ?, ?, ?, ?)",
                params![
                    ban.ip.to_string(),
                    ban.reason,
                    ban.source.to_string(),
                    ban.created_at.to_rfc3339(),
                    ban.expires_at.map(|t| t.to_rfc3339()),
                    ban.ban_count
                ],
            )?;
            Ok(conn.last_insert_rowid())
        }
    }

    /// Remove a ban by IP
    pub fn remove_ban(&self, ip: &IpAddr) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let rows = conn.execute("DELETE FROM bans WHERE ip = ?", [ip.to_string()])?;
        Ok(rows > 0)
    }

    /// Get a ban by IP
    pub fn get_ban(&self, ip: &IpAddr) -> Result<Option<Ban>> {
        let conn = self.conn.lock().unwrap();

        conn.query_row(
            "SELECT id, ip, reason, source, created_at, expires_at, ban_count FROM bans WHERE ip = ?",
            [ip.to_string()],
            |row| {
                Ok(Ban {
                    id: Some(row.get(0)?),
                    ip: row.get::<_, String>(1)?.parse().unwrap(),
                    reason: row.get(2)?,
                    source: row.get::<_, String>(3)?.parse().unwrap_or(BanSource::Manual),
                    created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(4)?)
                        .unwrap()
                        .with_timezone(&Utc),
                    expires_at: row.get::<_, Option<String>>(5)?.map(|s| {
                        DateTime::parse_from_rfc3339(&s)
                            .unwrap()
                            .with_timezone(&Utc)
                    }),
                    ban_count: row.get(6)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
    }

    /// Get all active bans (not expired)
    pub fn get_active_bans(&self) -> Result<Vec<Ban>> {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().to_rfc3339();

        let mut stmt = conn.prepare(
            "SELECT id, ip, reason, source, created_at, expires_at, ban_count FROM bans
             WHERE expires_at IS NULL OR expires_at > ?",
        )?;

        let bans = stmt
            .query_map([now], |row| {
                Ok(Ban {
                    id: Some(row.get(0)?),
                    ip: row.get::<_, String>(1)?.parse().unwrap(),
                    reason: row.get(2)?,
                    source: row.get::<_, String>(3)?.parse().unwrap_or(BanSource::Manual),
                    created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(4)?)
                        .unwrap()
                        .with_timezone(&Utc),
                    expires_at: row.get::<_, Option<String>>(5)?.map(|s| {
                        DateTime::parse_from_rfc3339(&s)
                            .unwrap()
                            .with_timezone(&Utc)
                    }),
                    ban_count: row.get(6)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(bans)
    }

    /// Get expired bans for cleanup
    pub fn get_expired_bans(&self) -> Result<Vec<Ban>> {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().to_rfc3339();

        let mut stmt = conn.prepare(
            "SELECT id, ip, reason, source, created_at, expires_at, ban_count FROM bans
             WHERE expires_at IS NOT NULL AND expires_at <= ?",
        )?;

        let bans = stmt
            .query_map([now], |row| {
                Ok(Ban {
                    id: Some(row.get(0)?),
                    ip: row.get::<_, String>(1)?.parse().unwrap(),
                    reason: row.get(2)?,
                    source: row.get::<_, String>(3)?.parse().unwrap_or(BanSource::Manual),
                    created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(4)?)
                        .unwrap()
                        .with_timezone(&Utc),
                    expires_at: row.get::<_, Option<String>>(5)?.map(|s| {
                        DateTime::parse_from_rfc3339(&s)
                            .unwrap()
                            .with_timezone(&Utc)
                    }),
                    ban_count: row.get(6)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(bans)
    }

    // ==================== Event Operations ====================

    /// Record an attack event
    pub fn add_event(&self, event: &AttackEvent) -> Result<i64> {
        let conn = self.conn.lock().unwrap();

        conn.execute(
            "INSERT INTO events (ip, timestamp, service, event_type, details, log_line) VALUES (?, ?, ?, ?, ?, ?)",
            params![
                event.ip.to_string(),
                event.timestamp.to_rfc3339(),
                event.service,
                event.event_type.to_string(),
                event.details,
                event.log_line
            ],
        )?;

        Ok(conn.last_insert_rowid())
    }

    /// Count events for an IP within a time window
    pub fn count_events_in_window(
        &self,
        ip: &IpAddr,
        service: &str,
        window_secs: u64,
    ) -> Result<u32> {
        let conn = self.conn.lock().unwrap();
        let since = (Utc::now() - chrono::Duration::seconds(window_secs as i64)).to_rfc3339();

        let count: u32 = conn.query_row(
            "SELECT COUNT(*) FROM events WHERE ip = ? AND service = ? AND timestamp > ?",
            params![ip.to_string(), service, since],
            |row| row.get(0),
        )?;

        Ok(count)
    }

    /// Get recent events
    pub fn get_recent_events(&self, limit: u32) -> Result<Vec<AttackEvent>> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT id, ip, timestamp, service, event_type, details, log_line
             FROM events ORDER BY timestamp DESC LIMIT ?",
        )?;

        let events = stmt
            .query_map([limit], |row| {
                let event_type_str: String = row.get(4)?;
                let event_type = if event_type_str == "failed_auth" {
                    AttackEventType::FailedAuth
                } else if event_type_str == "invalid_user" {
                    AttackEventType::InvalidUser
                } else if event_type_str == "brute_force" {
                    AttackEventType::BruteForce
                } else if event_type_str == "port_scan" {
                    AttackEventType::PortScan
                } else if event_type_str == "exploit" {
                    AttackEventType::Exploit
                } else if event_type_str == "rate_limit" {
                    AttackEventType::RateLimit
                } else {
                    AttackEventType::Other(event_type_str)
                };

                Ok(AttackEvent {
                    id: Some(row.get(0)?),
                    ip: row.get::<_, String>(1)?.parse().unwrap(),
                    timestamp: DateTime::parse_from_rfc3339(&row.get::<_, String>(2)?)
                        .unwrap()
                        .with_timezone(&Utc),
                    service: row.get(3)?,
                    event_type,
                    details: row.get(5)?,
                    log_line: row.get(6)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(events)
    }

    // ==================== Intel Operations ====================

    /// Save attacker intelligence
    pub fn save_intel(&self, intel: &AttackerIntel) -> Result<()> {
        let conn = self.conn.lock().unwrap();

        conn.execute(
            r#"INSERT OR REPLACE INTO intel (
                ip, gathered_at, country, country_code, city, region,
                latitude, longitude, timezone, asn, as_org, isp, reverse_dns,
                whois_org, whois_registrar, whois_abuse_contact, whois_raw,
                is_tor_exit, is_vpn, is_proxy, is_hosting, threat_score,
                open_ports, hostnames, shodan_tags
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
            params![
                intel.ip,
                intel.gathered_at.map(|t| t.to_rfc3339()),
                intel.country,
                intel.country_code,
                intel.city,
                intel.region,
                intel.latitude,
                intel.longitude,
                intel.timezone,
                intel.asn,
                intel.as_org,
                intel.isp,
                intel.reverse_dns,
                intel.whois_org,
                intel.whois_registrar,
                intel.whois_abuse_contact,
                intel.whois_raw,
                intel.is_tor_exit,
                intel.is_vpn,
                intel.is_proxy,
                intel.is_hosting,
                intel.threat_score,
                intel.open_ports.as_ref().map(|p| serde_json::to_string(p).ok()).flatten(),
                intel.hostnames.as_ref().map(|h| serde_json::to_string(h).ok()).flatten(),
                intel.shodan_tags.as_ref().map(|t| serde_json::to_string(t).ok()).flatten(),
            ],
        )?;

        Ok(())
    }

    /// Get intelligence for an IP
    pub fn get_intel(&self, ip: &str) -> Result<Option<AttackerIntel>> {
        let conn = self.conn.lock().unwrap();

        conn.query_row(
            r#"SELECT ip, gathered_at, country, country_code, city, region,
                latitude, longitude, timezone, asn, as_org, isp, reverse_dns,
                whois_org, whois_registrar, whois_abuse_contact, whois_raw,
                is_tor_exit, is_vpn, is_proxy, is_hosting, threat_score,
                open_ports, hostnames, shodan_tags
               FROM intel WHERE ip = ?"#,
            [ip],
            |row| {
                Ok(AttackerIntel {
                    ip: row.get(0)?,
                    gathered_at: row
                        .get::<_, Option<String>>(1)?
                        .map(|s| DateTime::parse_from_rfc3339(&s).unwrap().with_timezone(&Utc)),
                    country: row.get(2)?,
                    country_code: row.get(3)?,
                    city: row.get(4)?,
                    region: row.get(5)?,
                    latitude: row.get(6)?,
                    longitude: row.get(7)?,
                    timezone: row.get(8)?,
                    asn: row.get(9)?,
                    as_org: row.get(10)?,
                    isp: row.get(11)?,
                    reverse_dns: row.get(12)?,
                    whois_org: row.get(13)?,
                    whois_registrar: row.get(14)?,
                    whois_abuse_contact: row.get(15)?,
                    whois_raw: row.get(16)?,
                    is_tor_exit: row.get::<_, Option<i32>>(17)?.map(|v| v != 0),
                    is_vpn: row.get::<_, Option<i32>>(18)?.map(|v| v != 0),
                    is_proxy: row.get::<_, Option<i32>>(19)?.map(|v| v != 0),
                    is_hosting: row.get::<_, Option<i32>>(20)?.map(|v| v != 0),
                    threat_score: row.get::<_, Option<i32>>(21)?.map(|v| v as u32),
                    open_ports: row
                        .get::<_, Option<String>>(22)?
                        .and_then(|s| serde_json::from_str(&s).ok()),
                    hostnames: row
                        .get::<_, Option<String>>(23)?
                        .and_then(|s| serde_json::from_str(&s).ok()),
                    shodan_tags: row
                        .get::<_, Option<String>>(24)?
                        .and_then(|s| serde_json::from_str(&s).ok()),
                })
            },
        )
        .optional()
        .map_err(Into::into)
    }

    // ==================== Whitelist Operations ====================

    /// Add IP to whitelist
    pub fn add_whitelist(&self, entry: &WhitelistEntry) -> Result<i64> {
        let conn = self.conn.lock().unwrap();

        conn.execute(
            "INSERT OR REPLACE INTO whitelist (ip, comment, created_at) VALUES (?, ?, ?)",
            params![
                entry.ip.to_string(),
                entry.comment,
                entry.created_at.to_rfc3339()
            ],
        )?;

        Ok(conn.last_insert_rowid())
    }

    /// Remove IP from whitelist
    pub fn remove_whitelist(&self, ip: &IpAddr) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let rows = conn.execute("DELETE FROM whitelist WHERE ip = ?", [ip.to_string()])?;
        Ok(rows > 0)
    }

    /// Check if IP is whitelisted
    pub fn is_whitelisted(&self, ip: &IpAddr) -> Result<bool> {
        let conn = self.conn.lock().unwrap();

        let count: u32 = conn.query_row(
            "SELECT COUNT(*) FROM whitelist WHERE ip = ?",
            [ip.to_string()],
            |row| row.get(0),
        )?;

        Ok(count > 0)
    }

    /// Get all whitelist entries
    pub fn get_whitelist(&self) -> Result<Vec<WhitelistEntry>> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare("SELECT id, ip, comment, created_at FROM whitelist")?;

        let entries = stmt
            .query_map([], |row| {
                Ok(WhitelistEntry {
                    id: Some(row.get(0)?),
                    ip: row.get::<_, String>(1)?.parse().unwrap(),
                    comment: row.get(2)?,
                    created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(3)?)
                        .unwrap()
                        .with_timezone(&Utc),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(entries)
    }

    // ==================== Activity Log Operations ====================

    /// Log an activity
    pub fn log_activity(&self, action: ActivityAction, ip: Option<&IpAddr>, details: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();

        conn.execute(
            "INSERT INTO activity_log (timestamp, action, ip, details) VALUES (?, ?, ?, ?)",
            params![
                Utc::now().to_rfc3339(),
                action.to_string(),
                ip.map(|i| i.to_string()),
                details
            ],
        )?;

        Ok(())
    }

    /// Get recent activity
    pub fn get_recent_activity(&self, limit: u32) -> Result<Vec<ActivityLog>> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT id, timestamp, action, ip, details FROM activity_log ORDER BY timestamp DESC LIMIT ?",
        )?;

        let logs = stmt
            .query_map([limit], |row| {
                let action_str: String = row.get(2)?;
                let action = match action_str.as_str() {
                    "BAN" => ActivityAction::Ban,
                    "UNBAN" => ActivityAction::Unban,
                    "WHITELIST" => ActivityAction::Whitelist,
                    "UNWHITELIST" => ActivityAction::UnWhitelist,
                    "INTEL" => ActivityAction::IntelGathered,
                    "START" => ActivityAction::DaemonStart,
                    "STOP" => ActivityAction::DaemonStop,
                    "RELOAD" => ActivityAction::ConfigReload,
                    _ => ActivityAction::Ban,
                };

                Ok(ActivityLog {
                    id: Some(row.get(0)?),
                    timestamp: DateTime::parse_from_rfc3339(&row.get::<_, String>(1)?)
                        .unwrap()
                        .with_timezone(&Utc),
                    action,
                    ip: row
                        .get::<_, Option<String>>(3)?
                        .and_then(|s| s.parse().ok()),
                    details: row.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(logs)
    }

    // ==================== Statistics ====================

    /// Get attack statistics
    pub fn get_stats(&self) -> Result<AttackStats> {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now();
        let today_start = now.date_naive().and_hms_opt(0, 0, 0).unwrap();
        let hour_ago = (now - chrono::Duration::hours(1)).to_rfc3339();
        let today = today_start.and_utc().to_rfc3339();

        let total_bans: u64 =
            conn.query_row("SELECT COUNT(*) FROM bans", [], |row| row.get(0))?;

        let active_bans: u64 = conn.query_row(
            "SELECT COUNT(*) FROM bans WHERE expires_at IS NULL OR expires_at > ?",
            [now.to_rfc3339()],
            |row| row.get(0),
        )?;

        let total_events: u64 =
            conn.query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))?;

        let events_today: u64 = conn.query_row(
            "SELECT COUNT(*) FROM events WHERE timestamp > ?",
            [&today],
            |row| row.get(0),
        )?;

        let events_this_hour: u64 = conn.query_row(
            "SELECT COUNT(*) FROM events WHERE timestamp > ?",
            [&hour_ago],
            |row| row.get(0),
        )?;

        // Top countries
        let mut stmt = conn.prepare(
            "SELECT i.country_code, COUNT(*) as cnt FROM events e
             JOIN intel i ON e.ip = i.ip
             WHERE i.country_code IS NOT NULL
             GROUP BY i.country_code ORDER BY cnt DESC LIMIT 10",
        )?;
        let top_countries: Vec<(String, u64)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .filter_map(|r| r.ok())
            .collect();

        // Top ASNs
        let mut stmt = conn.prepare(
            "SELECT i.as_org, COUNT(*) as cnt FROM events e
             JOIN intel i ON e.ip = i.ip
             WHERE i.as_org IS NOT NULL
             GROUP BY i.as_org ORDER BY cnt DESC LIMIT 10",
        )?;
        let top_asns: Vec<(String, u64)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .filter_map(|r| r.ok())
            .collect();

        // Events by service
        let mut stmt = conn.prepare(
            "SELECT service, COUNT(*) as cnt FROM events GROUP BY service ORDER BY cnt DESC",
        )?;
        let events_by_service: Vec<(String, u64)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .filter_map(|r| r.ok())
            .collect();

        // Events by type
        let mut stmt = conn.prepare(
            "SELECT event_type, COUNT(*) as cnt FROM events GROUP BY event_type ORDER BY cnt DESC",
        )?;
        let events_by_type: Vec<(String, u64)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .filter_map(|r| r.ok())
            .collect();

        Ok(AttackStats {
            total_bans,
            active_bans,
            total_events,
            events_today,
            events_this_hour,
            top_countries,
            top_asns,
            events_by_service,
            events_by_type,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_ban_operations() {
        let db = Database::open_memory().unwrap();

        let ban = Ban::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            "Test ban".to_string(),
            BanSource::Manual,
            Some(3600),
        );

        // Add ban
        let id = db.add_ban(&ban).unwrap();
        assert!(id > 0);

        // Get ban
        let retrieved = db
            .get_ban(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)))
            .unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().reason, "Test ban");

        // Remove ban
        let removed = db
            .remove_ban(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)))
            .unwrap();
        assert!(removed);
    }

    #[test]
    fn test_whitelist_operations() {
        let db = Database::open_memory().unwrap();

        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let entry = WhitelistEntry::new(ip, Some("Trusted server".to_string()));

        db.add_whitelist(&entry).unwrap();
        assert!(db.is_whitelisted(&ip).unwrap());

        db.remove_whitelist(&ip).unwrap();
        assert!(!db.is_whitelisted(&ip).unwrap());
    }
}
