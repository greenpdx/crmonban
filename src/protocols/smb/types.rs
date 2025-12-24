//! SMB protocol types
//!
//! Defines all structures for SMB1, SMB2, and SMB3 protocol parsing.

use std::collections::HashMap;

/// SMB protocol version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmbVersion {
    /// SMB1/CIFS (legacy, insecure)
    Smb1,
    /// SMB 2.0
    Smb2_0,
    /// SMB 2.1
    Smb2_1,
    /// SMB 3.0
    Smb3_0,
    /// SMB 3.0.2
    Smb3_0_2,
    /// SMB 3.1.1
    Smb3_1_1,
    /// Unknown version
    Unknown,
}

impl SmbVersion {
    /// Check if this is SMB1 (legacy/insecure)
    pub fn is_smb1(&self) -> bool {
        matches!(self, SmbVersion::Smb1)
    }

    /// Check if this supports encryption
    pub fn supports_encryption(&self) -> bool {
        matches!(self, SmbVersion::Smb3_0 | SmbVersion::Smb3_0_2 | SmbVersion::Smb3_1_1)
    }
}

/// SMB dialect negotiation
#[derive(Debug, Clone)]
pub struct SmbDialect {
    pub version: SmbVersion,
    pub dialect_revision: u16,
    pub capabilities: u32,
    pub security_mode: u16,
}

/// SMB1 Commands
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Smb1Command {
    CreateDirectory = 0x00,
    DeleteDirectory = 0x01,
    Open = 0x02,
    Create = 0x03,
    Close = 0x04,
    Flush = 0x05,
    Delete = 0x06,
    Rename = 0x07,
    QueryInformation = 0x08,
    SetInformation = 0x09,
    Read = 0x0A,
    Write = 0x0B,
    LockByteRange = 0x0C,
    UnlockByteRange = 0x0D,
    CreateTemporary = 0x0E,
    CreateNew = 0x0F,
    CheckDirectory = 0x10,
    ProcessExit = 0x11,
    Seek = 0x12,
    LockAndRead = 0x13,
    WriteAndUnlock = 0x14,
    ReadRaw = 0x1A,
    ReadMpx = 0x1B,
    ReadMpxSecondary = 0x1C,
    WriteRaw = 0x1D,
    WriteMpx = 0x1E,
    WriteMpxSecondary = 0x1F,
    WriteComplete = 0x20,
    QueryServer = 0x21,
    SetInformation2 = 0x22,
    QueryInformation2 = 0x23,
    LockingAndX = 0x24,
    Transaction = 0x25,
    TransactionSecondary = 0x26,
    Ioctl = 0x27,
    IoctlSecondary = 0x28,
    Copy = 0x29,
    Move = 0x2A,
    Echo = 0x2B,
    WriteAndClose = 0x2C,
    OpenAndX = 0x2D,
    ReadAndX = 0x2E,
    WriteAndX = 0x2F,
    NewFileSize = 0x30,
    CloseAndTreeDisc = 0x31,
    Transaction2 = 0x32,
    Transaction2Secondary = 0x33,
    FindClose2 = 0x34,
    FindNotifyClose = 0x35,
    TreeConnect = 0x70,
    TreeDisconnect = 0x71,
    Negotiate = 0x72,
    SessionSetupAndX = 0x73,
    LogoffAndX = 0x74,
    TreeConnectAndX = 0x75,
    SecurityPackageAndX = 0x7E,
    QueryInformationDisk = 0x80,
    Search = 0x81,
    Find = 0x82,
    FindUnique = 0x83,
    FindClose = 0x84,
    NtTransact = 0xA0,
    NtTransactSecondary = 0xA1,
    NtCreateAndX = 0xA2,
    NtCancel = 0xA4,
    NtRename = 0xA5,
    OpenPrintFile = 0xC0,
    WritePrintFile = 0xC1,
    ClosePrintFile = 0xC2,
    GetPrintQueue = 0xC3,
    ReadBulk = 0xD8,
    WriteBulk = 0xD9,
    WriteBulkData = 0xDA,
    Invalid = 0xFE,
    NoAndxCommand = 0xFF,
}

impl From<u8> for Smb1Command {
    fn from(value: u8) -> Self {
        match value {
            0x00 => Smb1Command::CreateDirectory,
            0x01 => Smb1Command::DeleteDirectory,
            0x02 => Smb1Command::Open,
            0x03 => Smb1Command::Create,
            0x04 => Smb1Command::Close,
            0x05 => Smb1Command::Flush,
            0x06 => Smb1Command::Delete,
            0x07 => Smb1Command::Rename,
            0x25 => Smb1Command::Transaction,
            0x32 => Smb1Command::Transaction2,
            0x70 => Smb1Command::TreeConnect,
            0x71 => Smb1Command::TreeDisconnect,
            0x72 => Smb1Command::Negotiate,
            0x73 => Smb1Command::SessionSetupAndX,
            0x74 => Smb1Command::LogoffAndX,
            0x75 => Smb1Command::TreeConnectAndX,
            0xA0 => Smb1Command::NtTransact,
            0xA2 => Smb1Command::NtCreateAndX,
            _ => Smb1Command::Invalid,
        }
    }
}

/// SMB2/3 Commands
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Smb2Command {
    Negotiate = 0x0000,
    SessionSetup = 0x0001,
    Logoff = 0x0002,
    TreeConnect = 0x0003,
    TreeDisconnect = 0x0004,
    Create = 0x0005,
    Close = 0x0006,
    Flush = 0x0007,
    Read = 0x0008,
    Write = 0x0009,
    Lock = 0x000A,
    Ioctl = 0x000B,
    Cancel = 0x000C,
    Echo = 0x000D,
    QueryDirectory = 0x000E,
    ChangeNotify = 0x000F,
    QueryInfo = 0x0010,
    SetInfo = 0x0011,
    OplockBreak = 0x0012,
    Invalid = 0xFFFF,
}

impl From<u16> for Smb2Command {
    fn from(value: u16) -> Self {
        match value {
            0x0000 => Smb2Command::Negotiate,
            0x0001 => Smb2Command::SessionSetup,
            0x0002 => Smb2Command::Logoff,
            0x0003 => Smb2Command::TreeConnect,
            0x0004 => Smb2Command::TreeDisconnect,
            0x0005 => Smb2Command::Create,
            0x0006 => Smb2Command::Close,
            0x0007 => Smb2Command::Flush,
            0x0008 => Smb2Command::Read,
            0x0009 => Smb2Command::Write,
            0x000A => Smb2Command::Lock,
            0x000B => Smb2Command::Ioctl,
            0x000C => Smb2Command::Cancel,
            0x000D => Smb2Command::Echo,
            0x000E => Smb2Command::QueryDirectory,
            0x000F => Smb2Command::ChangeNotify,
            0x0010 => Smb2Command::QueryInfo,
            0x0011 => Smb2Command::SetInfo,
            0x0012 => Smb2Command::OplockBreak,
            _ => Smb2Command::Invalid,
        }
    }
}

/// SMB NT Status codes (subset of common ones)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NtStatus {
    Success = 0x00000000,
    Pending = 0x00000103,
    MoreProcessingRequired = 0xC0000016,
    BufferOverflow = 0x80000005,
    NoMoreFiles = 0x80000006,
    InvalidHandle = 0xC0000008,
    InvalidParameter = 0xC000000D,
    NoSuchFile = 0xC000000F,
    EndOfFile = 0xC0000011,
    MoreEntries = 0x00000105,
    NotImplemented = 0xC0000002,
    AccessDenied = 0xC0000022,
    ObjectNameInvalid = 0xC0000033,
    ObjectNameNotFound = 0xC0000034,
    ObjectNameCollision = 0xC0000035,
    ObjectPathInvalid = 0xC0000039,
    ObjectPathNotFound = 0xC000003A,
    ObjectPathSyntaxBad = 0xC000003B,
    SharingViolation = 0xC0000043,
    FileLockConflict = 0xC0000054,
    LockNotGranted = 0xC0000055,
    DeletePending = 0xC0000056,
    PrivilegeNotHeld = 0xC0000061,
    LogonFailure = 0xC000006D,
    AccountRestriction = 0xC000006E,
    InvalidLogonHours = 0xC000006F,
    InvalidWorkstation = 0xC0000070,
    PasswordExpired = 0xC0000071,
    AccountDisabled = 0xC0000072,
    BadNetworkName = 0xC00000CC,
    RequestNotAccepted = 0xC00000D0,
    PipeBusy = 0xC00000AE,
    PipeDisconnected = 0xC00000B0,
    PipeClosing = 0xC00000B1,
    PipeConnected = 0xC00000B2,
    PipeListening = 0xC00000B3,
    NetworkNameDeleted = 0xC00000C9,
    UserSessionDeleted = 0xC0000203,
    NetworkSessionExpired = 0xC000035C,
    Unknown = 0xFFFFFFFF,
}

impl From<u32> for NtStatus {
    fn from(value: u32) -> Self {
        match value {
            0x00000000 => NtStatus::Success,
            0x00000103 => NtStatus::Pending,
            0xC0000016 => NtStatus::MoreProcessingRequired,
            0xC0000022 => NtStatus::AccessDenied,
            0xC000006D => NtStatus::LogonFailure,
            0xC0000072 => NtStatus::AccountDisabled,
            0xC00000CC => NtStatus::BadNetworkName,
            _ => NtStatus::Unknown,
        }
    }
}

impl NtStatus {
    /// Check if status indicates success
    pub fn is_success(&self) -> bool {
        matches!(self, NtStatus::Success | NtStatus::Pending | NtStatus::MoreEntries)
    }

    /// Check if status indicates authentication failure
    pub fn is_auth_failure(&self) -> bool {
        matches!(
            self,
            NtStatus::LogonFailure
                | NtStatus::AccountDisabled
                | NtStatus::AccountRestriction
                | NtStatus::PasswordExpired
                | NtStatus::InvalidLogonHours
                | NtStatus::InvalidWorkstation
        )
    }
}

/// SMB1 Header
#[derive(Debug, Clone)]
pub struct Smb1Header {
    pub command: Smb1Command,
    pub status: u32,
    pub flags: u8,
    pub flags2: u16,
    pub pid_high: u16,
    pub signature: [u8; 8],
    pub tid: u16,
    pub pid: u16,
    pub uid: u16,
    pub mid: u16,
}

/// SMB2/3 Header
#[derive(Debug, Clone)]
pub struct Smb2Header {
    pub credit_charge: u16,
    pub status: NtStatus,
    pub command: Smb2Command,
    pub credit_request: u16,
    pub flags: u32,
    pub next_command: u32,
    pub message_id: u64,
    pub process_id: u32,
    pub tree_id: u32,
    pub session_id: u64,
    pub signature: [u8; 16],
}

/// SMB Tree Connect information
#[derive(Debug, Clone)]
pub struct TreeConnect {
    pub tree_id: u32,
    pub share_name: String,
    pub share_type: ShareType,
    pub access_mask: u32,
}

/// SMB Share types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareType {
    Disk,
    Pipe,
    Print,
    Unknown,
}

impl From<u8> for ShareType {
    fn from(value: u8) -> Self {
        match value {
            0x01 => ShareType::Disk,
            0x02 => ShareType::Pipe,
            0x03 => ShareType::Print,
            _ => ShareType::Unknown,
        }
    }
}

/// SMB File operation
#[derive(Debug, Clone)]
pub struct FileOperation {
    pub file_id: u64,
    pub filename: String,
    pub operation: FileOpType,
    pub access_mask: u32,
    pub size: u64,
}

/// File operation types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileOpType {
    Create,
    Open,
    Read,
    Write,
    Delete,
    Rename,
    Close,
    QueryInfo,
    SetInfo,
}

/// SMB Session information
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub session_id: u64,
    pub username: Option<String>,
    pub domain: Option<String>,
    pub workstation: Option<String>,
    pub authenticated: bool,
}

/// NTLMSSP authentication data
#[derive(Debug, Clone, Default)]
pub struct NtlmsspData {
    pub message_type: u32,
    pub domain: Option<String>,
    pub username: Option<String>,
    pub workstation: Option<String>,
    pub ntlm_response: Option<Vec<u8>>,
}

/// SMB Transaction (parsed)
#[derive(Debug, Clone)]
pub struct SmbTransaction {
    pub id: u64,
    pub command: SmbCommandType,
    pub status: NtStatus,
    pub share_name: Option<String>,
    pub filename: Option<String>,
    pub username: Option<String>,
    pub domain: Option<String>,
    pub request_size: u64,
    pub response_size: u64,
    pub timestamp: u64,
}

/// Unified SMB command type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmbCommandType {
    Negotiate,
    SessionSetup,
    Logoff,
    TreeConnect,
    TreeDisconnect,
    Create,
    Close,
    Read,
    Write,
    Ioctl,
    QueryInfo,
    SetInfo,
    QueryDirectory,
    ChangeNotify,
    Lock,
    Echo,
    Cancel,
    OplockBreak,
    Other(u16),
}

impl From<Smb2Command> for SmbCommandType {
    fn from(cmd: Smb2Command) -> Self {
        match cmd {
            Smb2Command::Negotiate => SmbCommandType::Negotiate,
            Smb2Command::SessionSetup => SmbCommandType::SessionSetup,
            Smb2Command::Logoff => SmbCommandType::Logoff,
            Smb2Command::TreeConnect => SmbCommandType::TreeConnect,
            Smb2Command::TreeDisconnect => SmbCommandType::TreeDisconnect,
            Smb2Command::Create => SmbCommandType::Create,
            Smb2Command::Close => SmbCommandType::Close,
            Smb2Command::Read => SmbCommandType::Read,
            Smb2Command::Write => SmbCommandType::Write,
            Smb2Command::Ioctl => SmbCommandType::Ioctl,
            Smb2Command::QueryInfo => SmbCommandType::QueryInfo,
            Smb2Command::SetInfo => SmbCommandType::SetInfo,
            Smb2Command::QueryDirectory => SmbCommandType::QueryDirectory,
            Smb2Command::ChangeNotify => SmbCommandType::ChangeNotify,
            Smb2Command::Lock => SmbCommandType::Lock,
            Smb2Command::Echo => SmbCommandType::Echo,
            Smb2Command::Cancel => SmbCommandType::Cancel,
            Smb2Command::OplockBreak => SmbCommandType::OplockBreak,
            Smb2Command::Flush => SmbCommandType::Other(0x0007),
            Smb2Command::Invalid => SmbCommandType::Other(0xFFFF),
        }
    }
}

/// Named pipe information
#[derive(Debug, Clone)]
pub struct NamedPipe {
    pub name: String,
    pub tree_id: u32,
    pub file_id: u64,
}

/// Common named pipes that may indicate malicious activity
pub const SUSPICIOUS_PIPES: &[&str] = &[
    "\\PIPE\\atsvc",      // Task Scheduler
    "\\PIPE\\svcctl",     // Service Control
    "\\PIPE\\samr",       // SAM Remote
    "\\PIPE\\lsarpc",     // LSA Remote
    "\\PIPE\\netlogon",   // Netlogon
    "\\PIPE\\srvsvc",     // Server Service
    "\\PIPE\\wkssvc",     // Workstation Service
    "\\PIPE\\winreg",     // Remote Registry
    "\\PIPE\\epmapper",   // Endpoint Mapper
    "\\PIPE\\eventlog",   // Event Log
    "\\PIPE\\spoolss",    // Print Spooler
    "\\PIPE\\browser",    // Browser
    "\\PIPE\\ntsvcs",     // NT Services
    "\\PIPE\\scerpc",     // Security Configuration
];

/// File extensions commonly targeted by ransomware
pub const RANSOMWARE_EXTENSIONS: &[&str] = &[
    ".encrypted", ".locked", ".crypto", ".crypt", ".enc",
    ".locky", ".cerber", ".zepto", ".thor", ".aesir",
    ".zzzzz", ".cryptolocker", ".cryptowall", ".ctbl",
    ".ecc", ".ezz", ".exx", ".vvv", ".xxx",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smb_version() {
        assert!(SmbVersion::Smb1.is_smb1());
        assert!(!SmbVersion::Smb3_0.is_smb1());
        assert!(SmbVersion::Smb3_0.supports_encryption());
        assert!(!SmbVersion::Smb2_0.supports_encryption());
    }

    #[test]
    fn test_nt_status() {
        assert!(NtStatus::Success.is_success());
        assert!(NtStatus::LogonFailure.is_auth_failure());
        assert!(!NtStatus::AccessDenied.is_auth_failure());
    }

    #[test]
    fn test_smb2_command() {
        assert_eq!(Smb2Command::from(0x0003), Smb2Command::TreeConnect);
        assert_eq!(Smb2Command::from(0x0005), Smb2Command::Create);
        assert_eq!(Smb2Command::from(0xFFFF), Smb2Command::Invalid);
    }
}
