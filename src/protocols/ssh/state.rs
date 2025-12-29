//! SSH per-flow state

use std::any::Any;
use std::time::Instant;

use crate::protocols::traits::ProtocolStateData;
use crate::types::protocols::SshVersionInfo;

/// SSH per-flow state
#[derive(Debug)]
pub struct SshState {
    /// Client version info
    pub client_version: Option<SshVersionInfo>,
    /// Server version info
    pub server_version: Option<SshVersionInfo>,
    /// Client HASSH hash
    pub client_hassh: Option<String>,
    /// Server HASSH hash
    pub server_hassh: Option<String>,
    /// HASSH raw string (for rule matching)
    pub hassh_string: Option<String>,
    /// Server HASSH raw string
    pub hassh_server_string: Option<String>,
    /// Detected suspicious HASSH
    pub suspicious_hassh: bool,
    /// Detected suspicious software
    pub suspicious_software: bool,
    /// Current username being authenticated
    pub current_username: Option<String>,
    /// Authentication failures in this flow
    pub auth_failures: u32,
    /// Authentication successes in this flow
    pub auth_successes: u32,
    /// Weak algorithms detected
    pub weak_algorithms: Vec<String>,
    /// Vulnerable version detected
    pub vulnerable_version: bool,
    /// CVEs for vulnerable version
    pub cves: Vec<String>,
    /// SSH-1 protocol detected
    pub ssh1_detected: bool,
    /// Connection start time
    pub start_time: Instant,
    /// Last packet time
    pub last_activity: Instant,
    /// Channel types opened
    pub channels: Vec<String>,
    /// Commands executed (via exec)
    pub commands: Vec<String>,
    /// Subsystems requested
    pub subsystems: Vec<String>,
}

impl SshState {
    /// Create new SSH state
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            client_version: None,
            server_version: None,
            client_hassh: None,
            server_hassh: None,
            hassh_string: None,
            hassh_server_string: None,
            suspicious_hassh: false,
            suspicious_software: false,
            current_username: None,
            auth_failures: 0,
            auth_successes: 0,
            weak_algorithms: Vec::new(),
            vulnerable_version: false,
            cves: Vec::new(),
            ssh1_detected: false,
            start_time: now,
            last_activity: now,
            channels: Vec::new(),
            commands: Vec::new(),
            subsystems: Vec::new(),
        }
    }

    /// Record client version
    pub fn record_client_version(&mut self, version: &str) {
        if let Some(info) = SshVersionInfo::parse(version) {
            // Check for SSH-1
            if info.protocol_version == 1 {
                self.ssh1_detected = true;
            }
            // Check for suspicious software
            if super::types::SUSPICIOUS_SOFTWARE.iter().any(|s|
                info.software.to_lowercase().contains(*s)
            ) {
                self.suspicious_software = true;
            }
            self.client_version = Some(info);
        }
        self.last_activity = Instant::now();
    }

    /// Record server version
    pub fn record_server_version(&mut self, version: &str) {
        if let Some(info) = SshVersionInfo::parse(version) {
            if info.protocol_version == 1 {
                self.ssh1_detected = true;
            }
            if super::types::SUSPICIOUS_SOFTWARE.iter().any(|s|
                info.software.to_lowercase().contains(*s)
            ) {
                self.suspicious_software = true;
            }
            self.server_version = Some(info);
        }
        self.last_activity = Instant::now();
    }

    /// Record client HASSH
    pub fn record_client_hassh(&mut self, hash: &str, raw_string: &str) {
        // Check against suspicious HASSH list
        if super::types::SUSPICIOUS_HASSH.contains(&hash) {
            self.suspicious_hassh = true;
        }
        self.client_hassh = Some(hash.to_string());
        self.hassh_string = Some(raw_string.to_string());
        self.last_activity = Instant::now();
    }

    /// Record server HASSH
    pub fn record_server_hassh(&mut self, hash: &str, raw_string: &str) {
        if super::types::SUSPICIOUS_HASSH.contains(&hash) {
            self.suspicious_hassh = true;
        }
        self.server_hassh = Some(hash.to_string());
        self.hassh_server_string = Some(raw_string.to_string());
        self.last_activity = Instant::now();
    }

    /// Record authentication attempt
    pub fn record_auth_attempt(&mut self, username: &str, success: bool) {
        self.current_username = Some(username.to_string());
        if success {
            self.auth_successes += 1;
        } else {
            self.auth_failures += 1;
        }
        self.last_activity = Instant::now();
    }

    /// Record weak algorithm
    pub fn add_weak_algorithm(&mut self, algo: String) {
        if !self.weak_algorithms.contains(&algo) {
            self.weak_algorithms.push(algo);
        }
    }

    /// Record channel open
    pub fn record_channel(&mut self, channel_type: &str) {
        self.channels.push(channel_type.to_string());
        self.last_activity = Instant::now();
    }

    /// Record command execution
    pub fn record_command(&mut self, command: &str) {
        self.commands.push(command.to_string());
        self.last_activity = Instant::now();
    }

    /// Record subsystem request
    pub fn record_subsystem(&mut self, subsystem: &str) {
        self.subsystems.push(subsystem.to_string());
        self.last_activity = Instant::now();
    }

    /// Check if this looks like a brute force attempt
    pub fn is_brute_force(&self, threshold: u32) -> bool {
        self.auth_failures >= threshold
    }
}

impl Default for SshState {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolStateData for SshState {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_state_creation() {
        let state = SshState::new();
        assert!(state.client_version.is_none());
        assert_eq!(state.auth_failures, 0);
    }

    #[test]
    fn test_version_recording() {
        let mut state = SshState::new();
        state.record_client_version("SSH-2.0-OpenSSH_8.9p1");
        assert!(state.client_version.is_some());
        assert!(!state.ssh1_detected);
    }

    #[test]
    fn test_ssh1_detection() {
        let mut state = SshState::new();
        state.record_client_version("SSH-1.99-OpenSSH_3.0");
        assert!(state.ssh1_detected);
    }

    #[test]
    fn test_suspicious_software() {
        let mut state = SshState::new();
        state.record_client_version("SSH-2.0-libssh_0.9.0");
        assert!(state.suspicious_software);
    }

    #[test]
    fn test_brute_force_tracking() {
        let mut state = SshState::new();
        for _ in 0..5 {
            state.record_auth_attempt("root", false);
        }
        assert!(state.is_brute_force(5));
        assert!(!state.is_brute_force(10));
    }
}
