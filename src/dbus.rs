//! D-Bus interface for crmonban daemon
//!
//! Provides a D-Bus service for controlling the daemon and receiving events.
//!
//! Service: org.crmonban.Daemon
//! Object Path: /org/crmonban/Daemon

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::RwLock;
use zbus::{interface, Connection};
use zbus::object_server::SignalEmitter;

use crate::models::BanSource;
use crate::Crmonban;

/// D-Bus interface name
pub const DBUS_INTERFACE: &str = "org.crmonban.Daemon";
/// D-Bus object path
pub const DBUS_PATH: &str = "/org/crmonban/Daemon";
/// D-Bus service name
pub const DBUS_NAME: &str = "org.crmonban.Daemon";

/// D-Bus interface implementation for crmonban
pub struct CrmonbanDbusInterface {
    crmonban: Arc<RwLock<Crmonban>>,
    start_time: Instant,
    events_processed: Arc<RwLock<u64>>,
}

impl CrmonbanDbusInterface {
    pub fn new(crmonban: Arc<RwLock<Crmonban>>, events_processed: Arc<RwLock<u64>>) -> Self {
        Self {
            crmonban,
            start_time: Instant::now(),
            events_processed,
        }
    }
}

/// Ban information returned via D-Bus
#[derive(Debug, Clone, zbus::zvariant::Type, serde::Serialize, serde::Deserialize)]
pub struct BanInfo {
    pub ip: String,
    pub reason: String,
    pub source: String,
    pub created_at: String,
    pub expires_at: String,
}

/// Status information returned via D-Bus
#[derive(Debug, Clone, zbus::zvariant::Type, serde::Serialize, serde::Deserialize)]
pub struct StatusInfo {
    pub running: bool,
    pub pid: u32,
    pub uptime_secs: u64,
    pub active_bans: u64,
    pub events_processed: u64,
    pub monitored_services: Vec<String>,
}

#[interface(name = "org.crmonban.Daemon")]
impl CrmonbanDbusInterface {
    /// Get daemon status
    async fn status(&self) -> StatusInfo {
        let crmonban = self.crmonban.read().await;
        let active_bans = crmonban.list_bans().map(|b| b.len() as u64).unwrap_or(0);
        let monitored_services: Vec<String> = crmonban
            .config()
            .services
            .iter()
            .filter(|(_, s)| s.enabled)
            .map(|(name, _)| name.clone())
            .collect();

        let events = *self.events_processed.read().await;

        StatusInfo {
            running: true,
            pid: std::process::id(),
            uptime_secs: self.start_time.elapsed().as_secs(),
            active_bans,
            events_processed: events,
            monitored_services,
        }
    }

    /// Ban an IP address
    /// Returns true on success, false on failure
    async fn ban(&self, ip: String, duration_secs: u32, reason: String) -> bool {
        let parsed_ip: IpAddr = match ip.parse() {
            Ok(ip) => ip,
            Err(_) => return false,
        };

        let crmonban = self.crmonban.read().await;
        let duration = if duration_secs > 0 {
            Some(duration_secs as i64)
        } else {
            None
        };

        crmonban
            .ban(parsed_ip, reason, BanSource::Manual, duration)
            .is_ok()
    }

    /// Unban an IP address
    /// Returns true if IP was banned and is now unbanned
    async fn unban(&self, ip: String) -> bool {
        let parsed_ip: IpAddr = match ip.parse() {
            Ok(ip) => ip,
            Err(_) => return false,
        };

        let crmonban = self.crmonban.read().await;
        crmonban.unban(&parsed_ip).unwrap_or(false)
    }

    /// Get list of active bans
    async fn get_bans(&self) -> Vec<BanInfo> {
        let crmonban = self.crmonban.read().await;
        crmonban
            .list_bans()
            .unwrap_or_default()
            .into_iter()
            .map(|b| BanInfo {
                ip: b.ip.to_string(),
                reason: b.reason,
                source: b.source.to_string(),
                created_at: b.created_at.to_rfc3339(),
                expires_at: b
                    .expires_at
                    .map(|e| e.to_rfc3339())
                    .unwrap_or_else(|| "permanent".to_string()),
            })
            .collect()
    }

    /// Check if an IP is banned
    async fn is_banned(&self, ip: String) -> bool {
        let parsed_ip: IpAddr = match ip.parse() {
            Ok(ip) => ip,
            Err(_) => return false,
        };

        let crmonban = self.crmonban.read().await;
        crmonban
            .get_ban(&parsed_ip)
            .map(|b| b.is_some())
            .unwrap_or(false)
    }

    /// Get number of active bans
    #[zbus(property)]
    async fn active_ban_count(&self) -> u64 {
        let crmonban = self.crmonban.read().await;
        crmonban.list_bans().map(|b| b.len() as u64).unwrap_or(0)
    }

    /// Check if daemon is running (always true if reachable)
    #[zbus(property)]
    async fn running(&self) -> bool {
        true
    }

    /// Get uptime in seconds
    #[zbus(property)]
    async fn uptime_seconds(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Get number of events processed
    #[zbus(property)]
    async fn events_processed(&self) -> u64 {
        *self.events_processed.read().await
    }

    // === Signals ===

    /// Emitted when an IP is banned
    #[zbus(signal)]
    pub async fn ban_added(
        emitter: &SignalEmitter<'_>,
        ip: &str,
        reason: &str,
        source: &str,
        duration_secs: u32,
    ) -> zbus::Result<()>;

    /// Emitted when an IP is unbanned
    #[zbus(signal)]
    pub async fn ban_removed(emitter: &SignalEmitter<'_>, ip: &str, reason: &str) -> zbus::Result<()>;

    /// Emitted when an attack is detected
    #[zbus(signal)]
    pub async fn attack_detected(
        emitter: &SignalEmitter<'_>,
        ip: &str,
        service: &str,
        event_type: &str,
    ) -> zbus::Result<()>;

    /// Emitted when daemon starts
    #[zbus(signal)]
    pub async fn daemon_started(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;

    /// Emitted when daemon is stopping
    #[zbus(signal)]
    pub async fn daemon_stopping(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;
}

/// D-Bus server handle for emitting signals
pub struct DbusServer {
    connection: Connection,
}

impl DbusServer {
    /// Start the D-Bus server
    pub async fn start(
        crmonban: Arc<RwLock<Crmonban>>,
        events_processed: Arc<RwLock<u64>>,
    ) -> zbus::Result<Self> {
        let interface = CrmonbanDbusInterface::new(crmonban, events_processed);

        let connection = Connection::system().await?;

        connection
            .object_server()
            .at(DBUS_PATH, interface)
            .await?;

        connection.request_name(DBUS_NAME).await?;

        tracing::info!("D-Bus server started on system bus as {}", DBUS_NAME);

        Ok(Self { connection })
    }

    /// Emit ban_added signal
    pub async fn emit_ban_added(
        &self,
        ip: &str,
        reason: &str,
        source: &str,
        duration_secs: u32,
    ) -> zbus::Result<()> {
        let emitter = self.signal_emitter().await?;
        CrmonbanDbusInterface::ban_added(&emitter, ip, reason, source, duration_secs).await
    }

    /// Emit ban_removed signal
    pub async fn emit_ban_removed(&self, ip: &str, reason: &str) -> zbus::Result<()> {
        let emitter = self.signal_emitter().await?;
        CrmonbanDbusInterface::ban_removed(&emitter, ip, reason).await
    }

    /// Emit attack_detected signal
    pub async fn emit_attack_detected(
        &self,
        ip: &str,
        service: &str,
        event_type: &str,
    ) -> zbus::Result<()> {
        let emitter = self.signal_emitter().await?;
        CrmonbanDbusInterface::attack_detected(&emitter, ip, service, event_type).await
    }

    /// Emit daemon_started signal
    pub async fn emit_daemon_started(&self) -> zbus::Result<()> {
        let emitter = self.signal_emitter().await?;
        CrmonbanDbusInterface::daemon_started(&emitter).await
    }

    /// Emit daemon_stopping signal
    pub async fn emit_daemon_stopping(&self) -> zbus::Result<()> {
        let emitter = self.signal_emitter().await?;
        CrmonbanDbusInterface::daemon_stopping(&emitter).await
    }

    async fn signal_emitter(&self) -> zbus::Result<SignalEmitter<'static>> {
        Ok(self.connection
            .object_server()
            .interface::<_, CrmonbanDbusInterface>(DBUS_PATH)
            .await?
            .signal_emitter()
            .to_owned())
    }
}

/// D-Bus client for CLI commands
pub struct DbusClient {
    connection: Connection,
}

impl DbusClient {
    /// Connect to the D-Bus service
    pub async fn connect() -> zbus::Result<Self> {
        let connection = Connection::system().await?;
        Ok(Self { connection })
    }

    /// Check if the daemon is available via D-Bus
    pub async fn is_daemon_available(&self) -> bool {
        use zbus::fdo::DBusProxy;

        let proxy = match DBusProxy::new(&self.connection).await {
            Ok(p) => p,
            Err(_) => return false,
        };

        proxy.name_has_owner(DBUS_NAME.try_into().unwrap()).await.unwrap_or(false)
    }

    /// Get daemon status
    pub async fn status(&self) -> zbus::Result<StatusInfo> {
        let proxy = self.proxy().await?;
        proxy.call_method("Status", &()).await?.body().deserialize()
    }

    /// Ban an IP
    pub async fn ban(&self, ip: &str, duration_secs: u32, reason: &str) -> zbus::Result<bool> {
        let proxy = self.proxy().await?;
        proxy
            .call_method("Ban", &(ip, duration_secs, reason))
            .await?
            .body()
            .deserialize()
    }

    /// Unban an IP
    pub async fn unban(&self, ip: &str) -> zbus::Result<bool> {
        let proxy = self.proxy().await?;
        proxy.call_method("Unban", &(ip,)).await?.body().deserialize()
    }

    /// Get list of bans
    pub async fn get_bans(&self) -> zbus::Result<Vec<BanInfo>> {
        let proxy = self.proxy().await?;
        proxy.call_method("GetBans", &()).await?.body().deserialize()
    }

    /// Check if IP is banned
    pub async fn is_banned(&self, ip: &str) -> zbus::Result<bool> {
        let proxy = self.proxy().await?;
        proxy.call_method("IsBanned", &(ip,)).await?.body().deserialize()
    }

    /// Get active ban count property
    pub async fn active_ban_count(&self) -> zbus::Result<u64> {
        let proxy = self.proxy().await?;
        proxy.get_property("ActiveBanCount").await
    }

    async fn proxy(&self) -> zbus::Result<zbus::proxy::Proxy<'_>> {
        zbus::proxy::Builder::new(&self.connection)
            .interface(DBUS_INTERFACE)?
            .path(DBUS_PATH)?
            .destination(DBUS_NAME)?
            .build()
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ban_info_struct() {
        let info = BanInfo {
            ip: "192.168.1.1".to_string(),
            reason: "test".to_string(),
            source: "manual".to_string(),
            created_at: "2024-01-01T00:00:00Z".to_string(),
            expires_at: "permanent".to_string(),
        };
        assert_eq!(info.ip, "192.168.1.1");
    }
}
