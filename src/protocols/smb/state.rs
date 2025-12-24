//! SMB per-flow state tracking
//!
//! Maintains state across packets for SMB connection.

use std::any::Any;
use std::collections::HashMap;

use super::types::*;
use crate::protocols::traits::ProtocolStateData;

/// SMB per-flow state
#[derive(Debug, Default)]
pub struct SmbState {
    /// Detected SMB version
    pub version: Option<SmbVersion>,

    /// Negotiated dialect
    pub dialect: Option<SmbDialect>,

    /// Current session info
    pub session: Option<SessionInfo>,

    /// Active tree connections (tree_id -> TreeConnect)
    pub trees: HashMap<u32, TreeConnect>,

    /// Open files (file_id -> FileOperation)
    pub files: HashMap<u64, FileOperation>,

    /// Named pipes in use
    pub pipes: HashMap<u64, NamedPipe>,

    /// NTLMSSP authentication state
    pub ntlmssp: Option<NtlmsspData>,

    /// Message ID tracking
    pub last_message_id: u64,

    /// Failed authentication attempts
    pub auth_failures: u32,

    /// Successful authentication
    pub authenticated: bool,

    /// Files accessed (for ransomware detection)
    pub files_accessed: Vec<String>,

    /// Files with suspicious extensions
    pub suspicious_files: Vec<String>,

    /// Is using encryption
    pub encrypted: bool,

    /// Is using signing
    pub signing: bool,
}

impl SmbState {
    /// Create new SMB state
    pub fn new() -> Self {
        Self::default()
    }

    /// Set negotiated version
    pub fn set_version(&mut self, version: SmbVersion) {
        self.version = Some(version);
    }

    /// Add tree connection
    pub fn add_tree(&mut self, tree_id: u32, share_name: String, share_type: ShareType) {
        self.trees.insert(tree_id, TreeConnect {
            tree_id,
            share_name,
            share_type,
            access_mask: 0,
        });
    }

    /// Remove tree connection
    pub fn remove_tree(&mut self, tree_id: u32) {
        self.trees.remove(&tree_id);
    }

    /// Get tree connection
    pub fn get_tree(&self, tree_id: u32) -> Option<&TreeConnect> {
        self.trees.get(&tree_id)
    }

    /// Add open file
    pub fn add_file(&mut self, file_id: u64, filename: String, operation: FileOpType) {
        // Track for ransomware detection
        self.files_accessed.push(filename.clone());

        // Check for suspicious extensions
        let lower = filename.to_lowercase();
        for ext in RANSOMWARE_EXTENSIONS {
            if lower.ends_with(ext) {
                self.suspicious_files.push(filename.clone());
                break;
            }
        }

        self.files.insert(file_id, FileOperation {
            file_id,
            filename,
            operation,
            access_mask: 0,
            size: 0,
        });
    }

    /// Close file
    pub fn close_file(&mut self, file_id: u64) {
        self.files.remove(&file_id);
    }

    /// Add named pipe
    pub fn add_pipe(&mut self, file_id: u64, pipe_name: String, tree_id: u32) {
        self.pipes.insert(file_id, NamedPipe {
            name: pipe_name,
            tree_id,
            file_id,
        });
    }

    /// Get named pipe
    pub fn get_pipe(&self, file_id: u64) -> Option<&NamedPipe> {
        self.pipes.get(&file_id)
    }

    /// Record authentication failure
    pub fn record_auth_failure(&mut self) {
        self.auth_failures += 1;
    }

    /// Record successful authentication
    pub fn record_auth_success(&mut self, username: String, domain: Option<String>) {
        self.authenticated = true;
        self.session = Some(SessionInfo {
            session_id: 0,
            username: Some(username),
            domain,
            workstation: None,
            authenticated: true,
        });
    }

    /// Check if SMB1 is being used (security concern)
    pub fn is_smb1(&self) -> bool {
        matches!(self.version, Some(SmbVersion::Smb1))
    }

    /// Check for potential ransomware activity
    pub fn check_ransomware_indicators(&self) -> bool {
        // Many files accessed with suspicious extensions
        if self.suspicious_files.len() > 5 {
            return true;
        }

        // Mass file operations
        if self.files_accessed.len() > 100 {
            return true;
        }

        false
    }

    /// Check for lateral movement indicators
    pub fn check_lateral_movement(&self) -> bool {
        // Check for suspicious named pipe access
        for pipe in self.pipes.values() {
            let pipe_lower = pipe.name.to_lowercase();
            for suspicious in SUSPICIOUS_PIPES {
                if pipe_lower.contains(&suspicious.to_lowercase()) {
                    return true;
                }
            }
        }

        // Check for admin share access
        for tree in self.trees.values() {
            let share_lower = tree.share_name.to_lowercase();
            if share_lower.ends_with("$") &&
               (share_lower.starts_with("c$") ||
                share_lower.starts_with("admin$") ||
                share_lower.starts_with("ipc$")) {
                return true;
            }
        }

        false
    }

    /// Get current share name (if any)
    pub fn current_share(&self) -> Option<&str> {
        self.trees.values().next().map(|t| t.share_name.as_str())
    }

    /// Get current username (if authenticated)
    pub fn current_user(&self) -> Option<&str> {
        self.session.as_ref()?.username.as_deref()
    }

    /// Get current domain (if authenticated)
    pub fn current_domain(&self) -> Option<&str> {
        self.session.as_ref()?.domain.as_deref()
    }
}

impl ProtocolStateData for SmbState {
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
    fn test_smb_state_new() {
        let state = SmbState::new();
        assert!(state.version.is_none());
        assert!(!state.authenticated);
        assert_eq!(state.auth_failures, 0);
    }

    #[test]
    fn test_tree_management() {
        let mut state = SmbState::new();
        state.add_tree(1, "\\\\server\\share".to_string(), ShareType::Disk);

        assert!(state.get_tree(1).is_some());
        assert_eq!(state.get_tree(1).unwrap().share_name, "\\\\server\\share");

        state.remove_tree(1);
        assert!(state.get_tree(1).is_none());
    }

    #[test]
    fn test_ransomware_detection() {
        let mut state = SmbState::new();

        // Add suspicious files
        for i in 0..10 {
            state.add_file(i, format!("file{}.encrypted", i), FileOpType::Write);
        }

        assert!(state.check_ransomware_indicators());
    }

    #[test]
    fn test_lateral_movement_detection() {
        let mut state = SmbState::new();
        state.add_tree(1, "\\\\server\\ADMIN$".to_string(), ShareType::Disk);

        assert!(state.check_lateral_movement());
    }
}
