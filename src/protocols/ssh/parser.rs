//! SSH protocol parser
//!
//! Parses SSH protocol messages to extract version, key exchange, and auth events.

use crmonban_types::protocols::{
    SshEvent, SshAuthMethod, SshNegotiatedAlgorithms, SshVersionInfo,
    HasshFingerprint,
};
use tracing::{debug, trace};

/// SSH message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SshMsgType {
    Disconnect = 1,
    Ignore = 2,
    Unimplemented = 3,
    Debug = 4,
    ServiceRequest = 5,
    ServiceAccept = 6,
    KexInit = 20,
    NewKeys = 21,
    KexdhInit = 30,
    KexdhReply = 31,
    UserauthRequest = 50,
    UserauthFailure = 51,
    UserauthSuccess = 52,
    UserauthBanner = 53,
    GlobalRequest = 80,
    RequestSuccess = 81,
    RequestFailure = 82,
    ChannelOpen = 90,
    ChannelOpenConfirmation = 91,
    ChannelOpenFailure = 92,
    ChannelWindowAdjust = 93,
    ChannelData = 94,
    ChannelExtendedData = 95,
    ChannelEof = 96,
    ChannelClose = 97,
    ChannelRequest = 98,
    ChannelSuccess = 99,
    ChannelFailure = 100,
}

impl TryFrom<u8> for SshMsgType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(SshMsgType::Disconnect),
            2 => Ok(SshMsgType::Ignore),
            3 => Ok(SshMsgType::Unimplemented),
            4 => Ok(SshMsgType::Debug),
            5 => Ok(SshMsgType::ServiceRequest),
            6 => Ok(SshMsgType::ServiceAccept),
            20 => Ok(SshMsgType::KexInit),
            21 => Ok(SshMsgType::NewKeys),
            30 => Ok(SshMsgType::KexdhInit),
            31 => Ok(SshMsgType::KexdhReply),
            50 => Ok(SshMsgType::UserauthRequest),
            51 => Ok(SshMsgType::UserauthFailure),
            52 => Ok(SshMsgType::UserauthSuccess),
            53 => Ok(SshMsgType::UserauthBanner),
            80 => Ok(SshMsgType::GlobalRequest),
            81 => Ok(SshMsgType::RequestSuccess),
            82 => Ok(SshMsgType::RequestFailure),
            90 => Ok(SshMsgType::ChannelOpen),
            91 => Ok(SshMsgType::ChannelOpenConfirmation),
            92 => Ok(SshMsgType::ChannelOpenFailure),
            93 => Ok(SshMsgType::ChannelWindowAdjust),
            94 => Ok(SshMsgType::ChannelData),
            95 => Ok(SshMsgType::ChannelExtendedData),
            96 => Ok(SshMsgType::ChannelEof),
            97 => Ok(SshMsgType::ChannelClose),
            98 => Ok(SshMsgType::ChannelRequest),
            99 => Ok(SshMsgType::ChannelSuccess),
            100 => Ok(SshMsgType::ChannelFailure),
            _ => Err(()),
        }
    }
}

/// SSH parser for extracting protocol events
#[derive(Debug, Default)]
pub struct SshParser {
    /// Buffer for partial version string
    version_buffer: Vec<u8>,
    /// Have we seen the version exchange?
    version_seen: bool,
    /// Is this the client side?
    is_client: bool,
}

impl SshParser {
    /// Create new SSH parser
    pub fn new(is_client: bool) -> Self {
        Self {
            version_buffer: Vec::new(),
            version_seen: false,
            is_client,
        }
    }

    /// Check if payload looks like SSH
    pub fn is_ssh(payload: &[u8]) -> bool {
        // Check for SSH version string
        if payload.starts_with(b"SSH-") {
            return true;
        }

        // Check for SSH binary packet (after version exchange)
        // SSH packets start with 4-byte length
        if payload.len() >= 5 {
            let length = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
            // Sanity check: length should be reasonable (< 256KB)
            if length > 0 && length < 262144 && payload.len() >= 5 {
                // Check if padding length is valid
                let padding_length = payload[4] as usize;
                if padding_length >= 4 && padding_length <= 255 {
                    return true;
                }
            }
        }

        false
    }

    /// Parse SSH version string
    pub fn parse_version(payload: &[u8]) -> Option<SshEvent> {
        // SSH version string format: SSH-protoversion-softwareversion SP comments CR LF
        if !payload.starts_with(b"SSH-") {
            return None;
        }

        // Find line ending
        let line_end = payload.iter().position(|&b| b == b'\r' || b == b'\n')
            .unwrap_or(payload.len());

        let version_line = std::str::from_utf8(&payload[..line_end]).ok()?;
        let version_info = SshVersionInfo::parse(version_line)?;

        Some(SshEvent::VersionExchange {
            client_version: version_line.to_string(),
            server_version: None,
            protocol_version: version_info.protocol_version,
        })
    }

    /// Parse SSH binary packet
    pub fn parse_packet(&mut self, payload: &[u8]) -> Option<SshEvent> {
        if payload.len() < 6 {
            return None;
        }

        // SSH binary packet format:
        // uint32 packet_length
        // byte   padding_length
        // byte[n1] payload (n1 = packet_length - padding_length - 1)
        // byte[n2] random padding (n2 = padding_length)
        // byte[m]  mac (if mac enabled)

        let packet_length = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
        let padding_length = payload[4] as usize;

        // Validate lengths
        if packet_length < 2 || packet_length > 35000 {
            trace!("Invalid SSH packet length: {}", packet_length);
            return None;
        }

        let payload_offset = 5;
        let payload_length = packet_length.saturating_sub(padding_length).saturating_sub(1);

        if payload.len() < payload_offset + payload_length {
            return None;
        }

        let msg_type = payload[payload_offset];
        let msg_data = &payload[payload_offset + 1..payload_offset + payload_length];

        self.parse_message(msg_type, msg_data)
    }

    /// Parse SSH message by type
    fn parse_message(&mut self, msg_type: u8, data: &[u8]) -> Option<SshEvent> {
        match SshMsgType::try_from(msg_type) {
            Ok(SshMsgType::KexInit) => self.parse_kex_init(data),
            Ok(SshMsgType::UserauthRequest) => self.parse_userauth_request(data),
            Ok(SshMsgType::UserauthSuccess) => Some(self.make_auth_success()),
            Ok(SshMsgType::UserauthFailure) => Some(self.make_auth_failure(data)),
            Ok(SshMsgType::ChannelOpen) => self.parse_channel_open(data),
            Ok(SshMsgType::ChannelRequest) => self.parse_channel_request(data),
            _ => None,
        }
    }

    /// Parse SSH_MSG_KEXINIT
    fn parse_kex_init(&self, data: &[u8]) -> Option<SshEvent> {
        // SSH_MSG_KEXINIT format:
        // byte[16] cookie
        // name-list kex_algorithms
        // name-list server_host_key_algorithms
        // name-list encryption_algorithms_client_to_server
        // name-list encryption_algorithms_server_to_client
        // name-list mac_algorithms_client_to_server
        // name-list mac_algorithms_server_to_client
        // name-list compression_algorithms_client_to_server
        // name-list compression_algorithms_server_to_client
        // name-list languages_client_to_server
        // name-list languages_server_to_client
        // boolean first_kex_packet_follows
        // uint32 0 (reserved)

        if data.len() < 16 {
            return None;
        }

        // Skip cookie (16 bytes)
        let mut offset = 16;

        let kex_algorithms = self.read_name_list(data, &mut offset)?;
        let host_key_algorithms = self.read_name_list(data, &mut offset)?;
        let encryption_c2s = self.read_name_list(data, &mut offset)?;
        let encryption_s2c = self.read_name_list(data, &mut offset)?;
        let mac_c2s = self.read_name_list(data, &mut offset)?;
        let mac_s2c = self.read_name_list(data, &mut offset)?;
        let compression_c2s = self.read_name_list(data, &mut offset)?;
        let _compression_s2c = self.read_name_list(data, &mut offset)?;

        // Compute HASSH fingerprint
        // HASSH = MD5(kex;enc;mac;cmp)
        let hassh = HasshFingerprint::compute(
            &kex_algorithms,
            &encryption_c2s,
            &mac_c2s,
            &compression_c2s,
            !self.is_client,
        );

        if self.is_client {
            Some(SshEvent::KeyExchangeInit {
                hassh,
                kex_algorithms,
                host_key_algorithms,
                encryption_c2s,
                encryption_s2c,
                mac_c2s,
                mac_s2c,
                compression: compression_c2s,
            })
        } else {
            Some(SshEvent::ServerKexInit {
                hassh_server: hassh,
                selected_algorithms: None,
            })
        }
    }

    /// Parse SSH_MSG_USERAUTH_REQUEST
    fn parse_userauth_request(&self, data: &[u8]) -> Option<SshEvent> {
        // SSH_MSG_USERAUTH_REQUEST format:
        // string username
        // string service name (usually "ssh-connection")
        // string method name
        // ... method-specific data

        let mut offset = 0;
        let username = self.read_string(data, &mut offset)?;
        let _service = self.read_string(data, &mut offset)?;
        let method_name = self.read_string(data, &mut offset)?;

        let method = match method_name.as_str() {
            "password" => SshAuthMethod::Password,
            "publickey" => SshAuthMethod::PublicKey,
            "keyboard-interactive" => SshAuthMethod::KeyboardInteractive,
            "hostbased" => SshAuthMethod::HostBased,
            "gssapi-with-mic" | "gssapi-keyex" => SshAuthMethod::GssApi,
            "none" => SshAuthMethod::None,
            other => SshAuthMethod::Unknown(other.to_string()),
        };

        Some(SshEvent::AuthAttempt {
            username,
            method,
            success: false, // Will be updated when we see success/failure
            attempt_number: 0, // Tracked by analyzer
        })
    }

    /// Create auth success event
    fn make_auth_success(&self) -> SshEvent {
        SshEvent::AuthAttempt {
            username: String::new(),
            method: SshAuthMethod::Unknown("unknown".into()),
            success: true,
            attempt_number: 0,
        }
    }

    /// Parse auth failure and create event
    fn make_auth_failure(&self, _data: &[u8]) -> SshEvent {
        // Could parse available methods from failure message
        SshEvent::AuthAttempt {
            username: String::new(),
            method: SshAuthMethod::Unknown("unknown".into()),
            success: false,
            attempt_number: 0,
        }
    }

    /// Parse SSH_MSG_CHANNEL_OPEN
    fn parse_channel_open(&self, data: &[u8]) -> Option<SshEvent> {
        // SSH_MSG_CHANNEL_OPEN format:
        // string channel type
        // uint32 sender channel
        // uint32 initial window size
        // uint32 maximum packet size
        // ... type-specific data

        let mut offset = 0;
        let channel_type = self.read_string(data, &mut offset)?;
        let channel_id = self.read_u32(data, &mut offset)?;

        Some(SshEvent::ChannelOpen {
            channel_type,
            channel_id,
        })
    }

    /// Parse SSH_MSG_CHANNEL_REQUEST
    fn parse_channel_request(&self, data: &[u8]) -> Option<SshEvent> {
        // SSH_MSG_CHANNEL_REQUEST format:
        // uint32 recipient channel
        // string request type
        // boolean want reply
        // ... request-specific data

        let mut offset = 0;
        let _channel_id = self.read_u32(data, &mut offset)?;
        let request_type = self.read_string(data, &mut offset)?;
        let _want_reply = if offset < data.len() { data[offset] != 0 } else { false };
        offset += 1;

        let (command, subsystem) = match request_type.as_str() {
            "exec" => {
                let cmd = self.read_string(data, &mut offset);
                (cmd, None)
            }
            "subsystem" => {
                let sub = self.read_string(data, &mut offset);
                (None, sub)
            }
            _ => (None, None),
        };

        Some(SshEvent::ChannelRequest {
            request_type,
            command,
            subsystem,
        })
    }

    /// Read SSH string (uint32 length + data)
    fn read_string(&self, data: &[u8], offset: &mut usize) -> Option<String> {
        if *offset + 4 > data.len() {
            return None;
        }

        let length = u32::from_be_bytes([
            data[*offset],
            data[*offset + 1],
            data[*offset + 2],
            data[*offset + 3],
        ]) as usize;

        *offset += 4;

        if *offset + length > data.len() {
            return None;
        }

        let s = std::str::from_utf8(&data[*offset..*offset + length]).ok()?.to_string();
        *offset += length;
        Some(s)
    }

    /// Read SSH name-list (comma-separated in string)
    fn read_name_list(&self, data: &[u8], offset: &mut usize) -> Option<Vec<String>> {
        let s = self.read_string(data, offset)?;
        Some(s.split(',').map(|s| s.to_string()).collect())
    }

    /// Read uint32
    fn read_u32(&self, data: &[u8], offset: &mut usize) -> Option<u32> {
        if *offset + 4 > data.len() {
            return None;
        }

        let val = u32::from_be_bytes([
            data[*offset],
            data[*offset + 1],
            data[*offset + 2],
            data[*offset + 3],
        ]);

        *offset += 4;
        Some(val)
    }
}

/// Weak key exchange algorithms
pub const WEAK_KEX_ALGORITHMS: &[&str] = &[
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
    "ecdh-sha2-nistp256", // Considered weak by some standards
];

/// Weak encryption algorithms
pub const WEAK_CIPHERS: &[&str] = &[
    "3des-cbc",
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
    "blowfish-cbc",
    "cast128-cbc",
    "arcfour",
    "arcfour128",
    "arcfour256",
    "none",
];

/// Weak MAC algorithms
pub const WEAK_MACS: &[&str] = &[
    "hmac-md5",
    "hmac-md5-96",
    "hmac-sha1",
    "hmac-sha1-96",
    "hmac-ripemd160",
    "umac-64@openssh.com",
    "none",
];

/// Check if algorithm list contains weak algorithms
pub fn has_weak_algorithms(algorithms: &[String], weak_list: &[&str]) -> Vec<String> {
    algorithms.iter()
        .filter(|a| weak_list.iter().any(|w| a.eq_ignore_ascii_case(w)))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_ssh() {
        assert!(SshParser::is_ssh(b"SSH-2.0-OpenSSH_8.9p1"));
        assert!(SshParser::is_ssh(b"SSH-1.99-OpenSSH_3.9"));
        assert!(!SshParser::is_ssh(b"HTTP/1.1 200 OK"));
        assert!(!SshParser::is_ssh(b"GET / HTTP/1.1"));
    }

    #[test]
    fn test_parse_version() {
        let event = SshParser::parse_version(b"SSH-2.0-OpenSSH_8.9p1\r\n");
        assert!(event.is_some());

        if let Some(SshEvent::VersionExchange { client_version, protocol_version, .. }) = event {
            assert_eq!(client_version, "SSH-2.0-OpenSSH_8.9p1");
            assert_eq!(protocol_version, 2);
        } else {
            panic!("Expected VersionExchange event");
        }
    }

    #[test]
    fn test_weak_algorithms() {
        let algos = vec![
            "aes256-gcm@openssh.com".to_string(),
            "aes128-cbc".to_string(),
            "chacha20-poly1305@openssh.com".to_string(),
        ];

        let weak = has_weak_algorithms(&algos, WEAK_CIPHERS);
        assert_eq!(weak.len(), 1);
        assert_eq!(weak[0], "aes128-cbc");
    }

    #[test]
    fn test_msg_type_conversion() {
        assert_eq!(SshMsgType::try_from(20), Ok(SshMsgType::KexInit));
        assert_eq!(SshMsgType::try_from(50), Ok(SshMsgType::UserauthRequest));
        assert_eq!(SshMsgType::try_from(52), Ok(SshMsgType::UserauthSuccess));
        assert!(SshMsgType::try_from(255).is_err());
    }
}
