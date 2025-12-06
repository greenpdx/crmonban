//! Action execution
//!
//! Executes actions in response to detection events (ban, alert, reject, etc.)

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use crate::core::event::{DetectionEvent, DetectionAction, Severity};

/// Action configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionConfig {
    /// Enable automatic banning
    pub auto_ban: bool,
    /// Default ban duration (seconds)
    pub default_ban_duration: u64,
    /// Ban duration by severity
    pub ban_durations: HashMap<String, u64>,
    /// Minimum severity to auto-ban
    pub min_severity_to_ban: Severity,
    /// Rate limit for actions per IP
    pub rate_limit_per_ip: usize,
    /// Rate limit window (seconds)
    pub rate_limit_window: u64,
    /// Enable reject for inline mode
    pub enable_reject: bool,
    /// Log all actions
    pub log_actions: bool,
}

impl Default for ActionConfig {
    fn default() -> Self {
        let mut ban_durations = HashMap::new();
        ban_durations.insert("info".to_string(), 0); // No ban
        ban_durations.insert("low".to_string(), 300); // 5 minutes
        ban_durations.insert("medium".to_string(), 3600); // 1 hour
        ban_durations.insert("high".to_string(), 86400); // 24 hours
        ban_durations.insert("critical".to_string(), 604800); // 7 days

        Self {
            auto_ban: false,
            default_ban_duration: 3600,
            ban_durations,
            min_severity_to_ban: Severity::High,
            rate_limit_per_ip: 10,
            rate_limit_window: 60,
            enable_reject: false,
            log_actions: true,
        }
    }
}

/// Action to take
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Generate alert only
    Alert,
    /// Ban the source IP
    Ban {
        ip: IpAddr,
        duration: Duration,
        reason: String,
    },
    /// Reject the packet (for inline mode)
    Reject {
        packet_id: u32,
    },
    /// Drop the packet silently (for inline mode)
    Drop {
        packet_id: u32,
    },
    /// Rate limit the source
    RateLimit {
        ip: IpAddr,
        pps: u32,
    },
    /// No action
    None,
}

/// Result of action execution
#[derive(Debug, Clone)]
pub struct ActionResult {
    /// Action that was executed
    pub action: Action,
    /// Whether it succeeded
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Action executor
pub struct ActionExecutor {
    /// Configuration
    config: ActionConfig,
    /// Action history for rate limiting
    action_history: Arc<RwLock<HashMap<IpAddr, Vec<Instant>>>>,
    /// Statistics
    stats: Arc<RwLock<ActionStats>>,
}

/// Action statistics
#[derive(Debug, Clone, Default, Serialize)]
pub struct ActionStats {
    /// Total actions executed
    pub total_actions: u64,
    /// Successful actions
    pub successful_actions: u64,
    /// Failed actions
    pub failed_actions: u64,
    /// Bans executed
    pub bans_executed: u64,
    /// Rejections executed
    pub rejections_executed: u64,
    /// Rate limited actions
    pub rate_limited: u64,
}

impl ActionExecutor {
    /// Create a new action executor
    pub fn new(config: ActionConfig) -> Self {
        Self {
            config,
            action_history: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(ActionStats::default())),
        }
    }

    /// Determine action for an event
    pub fn determine_action(&self, event: &DetectionEvent) -> Action {
        // Check if event already has an action specified
        match event.action {
            DetectionAction::Drop => {
                if let Some(packet_id) = self.get_packet_id(event) {
                    return Action::Drop { packet_id };
                }
            }
            DetectionAction::Reject => {
                if let Some(packet_id) = self.get_packet_id(event) {
                    return Action::Reject { packet_id };
                }
            }
            DetectionAction::Ban => {
                let duration = self.get_ban_duration(event.severity);
                return Action::Ban {
                    ip: event.src_ip,
                    duration,
                    reason: event.message.clone(),
                };
            }
            _ => {}
        }

        // Auto-ban logic
        if self.config.auto_ban && event.severity >= self.config.min_severity_to_ban {
            // Check rate limit
            if self.check_rate_limit(event.src_ip) {
                let duration = self.get_ban_duration(event.severity);
                return Action::Ban {
                    ip: event.src_ip,
                    duration,
                    reason: event.message.clone(),
                };
            }
        }

        Action::Alert
    }

    /// Execute an action
    pub fn execute(&self, action: &Action) -> ActionResult {
        let timestamp = chrono::Utc::now();

        self.stats.write().total_actions += 1;

        let result = match action {
            Action::Alert => {
                // Alerts are just logged, no action needed
                ActionResult {
                    action: action.clone(),
                    success: true,
                    error: None,
                    timestamp,
                }
            }
            Action::Ban { ip, duration, reason } => {
                self.execute_ban(*ip, *duration, reason)
            }
            Action::Reject { packet_id } => {
                self.execute_reject(*packet_id)
            }
            Action::Drop { packet_id } => {
                self.execute_drop(*packet_id)
            }
            Action::RateLimit { ip, pps } => {
                self.execute_rate_limit(*ip, *pps)
            }
            Action::None => {
                ActionResult {
                    action: action.clone(),
                    success: true,
                    error: None,
                    timestamp,
                }
            }
        };

        if result.success {
            self.stats.write().successful_actions += 1;
        } else {
            self.stats.write().failed_actions += 1;
        }

        result
    }

    /// Execute a ban
    fn execute_ban(&self, ip: IpAddr, duration: Duration, reason: &str) -> ActionResult {
        if self.config.log_actions {
            info!(
                "BAN: {} for {} seconds - {}",
                ip,
                duration.as_secs(),
                reason
            );
        }

        // In a real implementation, this would call the nftables ban logic
        // For now, just record the action
        self.stats.write().bans_executed += 1;

        ActionResult {
            action: Action::Ban {
                ip,
                duration,
                reason: reason.to_string(),
            },
            success: true,
            error: None,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Execute a reject
    fn execute_reject(&self, packet_id: u32) -> ActionResult {
        if self.config.log_actions {
            debug!("REJECT: packet {}", packet_id);
        }

        // In a real implementation, this would set NFQUEUE verdict to REJECT
        self.stats.write().rejections_executed += 1;

        ActionResult {
            action: Action::Reject { packet_id },
            success: true,
            error: None,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Execute a drop
    fn execute_drop(&self, packet_id: u32) -> ActionResult {
        if self.config.log_actions {
            debug!("DROP: packet {}", packet_id);
        }

        // In a real implementation, this would set NFQUEUE verdict to DROP
        ActionResult {
            action: Action::Drop { packet_id },
            success: true,
            error: None,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Execute rate limiting
    fn execute_rate_limit(&self, ip: IpAddr, pps: u32) -> ActionResult {
        if self.config.log_actions {
            debug!("RATE_LIMIT: {} to {} pps", ip, pps);
        }

        // In a real implementation, this would configure nftables rate limiting
        ActionResult {
            action: Action::RateLimit { ip, pps },
            success: true,
            error: None,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Get ban duration for severity
    fn get_ban_duration(&self, severity: Severity) -> Duration {
        let severity_str = format!("{:?}", severity).to_lowercase();
        let seconds = self.config.ban_durations
            .get(&severity_str)
            .copied()
            .unwrap_or(self.config.default_ban_duration);
        Duration::from_secs(seconds)
    }

    /// Check rate limit for an IP
    fn check_rate_limit(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(self.config.rate_limit_window);

        let mut history = self.action_history.write();
        let actions = history.entry(ip).or_insert_with(Vec::new);

        // Remove old entries
        actions.retain(|t| now.duration_since(*t) < window);

        // Check limit
        if actions.len() >= self.config.rate_limit_per_ip {
            self.stats.write().rate_limited += 1;
            return false;
        }

        // Record this action
        actions.push(now);
        true
    }

    /// Get packet ID from event (placeholder)
    fn get_packet_id(&self, _event: &DetectionEvent) -> Option<u32> {
        // In a real implementation, this would extract the NFQUEUE packet ID
        None
    }

    /// Get statistics
    pub fn stats(&self) -> ActionStats {
        self.stats.read().clone()
    }

    /// Get configuration
    pub fn config(&self) -> &ActionConfig {
        &self.config
    }
}

impl Default for ActionExecutor {
    fn default() -> Self {
        Self::new(ActionConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::DetectionType;

    fn make_event(severity: Severity) -> DetectionEvent {
        DetectionEvent::new(
            DetectionType::PortScan,
            severity,
            "192.168.1.100".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            "Test event".to_string(),
        )
        .with_ports(12345, 22)
    }

    #[test]
    fn test_action_config_default() {
        let config = ActionConfig::default();
        assert!(!config.auto_ban);
        assert_eq!(config.min_severity_to_ban, Severity::High);
    }

    #[test]
    fn test_action_executor_creation() {
        let executor = ActionExecutor::default();
        assert_eq!(executor.stats().total_actions, 0);
    }

    #[test]
    fn test_determine_action_alert() {
        let executor = ActionExecutor::default();
        let event = make_event(Severity::Low);

        let action = executor.determine_action(&event);
        assert!(matches!(action, Action::Alert));
    }

    #[test]
    fn test_determine_action_auto_ban() {
        let mut config = ActionConfig::default();
        config.auto_ban = true;

        let executor = ActionExecutor::new(config);
        let event = make_event(Severity::Critical);

        let action = executor.determine_action(&event);
        assert!(matches!(action, Action::Ban { .. }));
    }

    #[test]
    fn test_execute_action() {
        let executor = ActionExecutor::default();

        let result = executor.execute(&Action::Alert);
        assert!(result.success);

        assert_eq!(executor.stats().total_actions, 1);
        assert_eq!(executor.stats().successful_actions, 1);
    }

    #[test]
    fn test_ban_duration_by_severity() {
        let executor = ActionExecutor::default();

        let low = executor.get_ban_duration(Severity::Low);
        let high = executor.get_ban_duration(Severity::High);
        let critical = executor.get_ban_duration(Severity::Critical);

        assert!(low < high);
        assert!(high < critical);
    }

    #[test]
    fn test_rate_limiting() {
        let mut config = ActionConfig::default();
        config.rate_limit_per_ip = 3;
        config.rate_limit_window = 60;

        let executor = ActionExecutor::new(config);
        let ip: IpAddr = "192.168.1.100".parse().unwrap();

        // First 3 should pass
        assert!(executor.check_rate_limit(ip));
        assert!(executor.check_rate_limit(ip));
        assert!(executor.check_rate_limit(ip));

        // 4th should be rate limited
        assert!(!executor.check_rate_limit(ip));
        assert_eq!(executor.stats().rate_limited, 1);
    }
}
