//! SMB protocol parser
//!
//! Parses SMB1, SMB2, and SMB3 protocol messages.


use async_trait::async_trait;

use crate::core::{PacketAnalysis, Direction};
use crate::signatures::ast::Protocol;
use crate::protocols::{
    ProtocolParser, ProtocolState, ParseResult, ProtocolAlert, Transaction, ProtocolRuleSet,
};
use super::types::*;
use super::state::SmbState;
use super::match_::SmbMatcher;

/// SMB Magic bytes
const SMB1_MAGIC: &[u8] = b"\xFFSMB";
const SMB2_MAGIC: &[u8] = b"\xFESMB";

/// SMB2 header size
const SMB2_HEADER_SIZE: usize = 64;

/// SMB1 header size
const SMB1_HEADER_SIZE: usize = 32;

/// NetBIOS session header size
const NETBIOS_HEADER_SIZE: usize = 4;

/// SMB Protocol Parser
pub struct SmbParser {
    /// Matcher for Suricata rule matching
    matcher: SmbMatcher,
}

impl SmbParser {
    /// Create new SMB parser
    pub fn new() -> Self {
        Self {
            matcher: SmbMatcher::new(),
        }
    }

    /// Parse NetBIOS session header (4 bytes)
    fn parse_netbios_header(data: &[u8]) -> Option<(u8, u32)> {
        if data.len() < NETBIOS_HEADER_SIZE {
            return None;
        }

        let msg_type = data[0];
        let length = ((data[1] as u32) << 16) | ((data[2] as u32) << 8) | (data[3] as u32);

        Some((msg_type, length))
    }

    /// Check if this is SMB1
    fn is_smb1(data: &[u8]) -> bool {
        data.len() >= SMB1_MAGIC.len() && &data[..SMB1_MAGIC.len()] == SMB1_MAGIC
    }

    /// Check if this is SMB2/3
    fn is_smb2(data: &[u8]) -> bool {
        data.len() >= SMB2_MAGIC.len() && &data[..SMB2_MAGIC.len()] == SMB2_MAGIC
    }

    /// Parse SMB1 header
    fn parse_smb1_header(data: &[u8]) -> Option<Smb1Header> {
        if data.len() < SMB1_HEADER_SIZE + 4 {
            return None;
        }

        // Skip magic (4 bytes)
        let data = &data[4..];

        let command = Smb1Command::from(data[0]);
        let status = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
        let flags = data[5];
        let flags2 = u16::from_le_bytes([data[6], data[7]]);
        let pid_high = u16::from_le_bytes([data[8], data[9]]);

        let mut signature = [0u8; 8];
        signature.copy_from_slice(&data[10..18]);

        let tid = u16::from_le_bytes([data[20], data[21]]);
        let pid = u16::from_le_bytes([data[22], data[23]]);
        let uid = u16::from_le_bytes([data[24], data[25]]);
        let mid = u16::from_le_bytes([data[26], data[27]]);

        Some(Smb1Header {
            command,
            status,
            flags,
            flags2,
            pid_high,
            signature,
            tid,
            pid,
            uid,
            mid,
        })
    }

    /// Parse SMB2/3 header
    fn parse_smb2_header(data: &[u8]) -> Option<Smb2Header> {
        if data.len() < SMB2_HEADER_SIZE {
            return None;
        }

        // Skip magic (4 bytes) and structure size (2 bytes)
        let credit_charge = u16::from_le_bytes([data[6], data[7]]);
        let status = NtStatus::from(u32::from_le_bytes([data[8], data[9], data[10], data[11]]));
        let command = Smb2Command::from(u16::from_le_bytes([data[12], data[13]]));
        let credit_request = u16::from_le_bytes([data[14], data[15]]);
        let flags = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
        let next_command = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
        let message_id = u64::from_le_bytes([
            data[24], data[25], data[26], data[27],
            data[28], data[29], data[30], data[31],
        ]);
        let process_id = u32::from_le_bytes([data[32], data[33], data[34], data[35]]);
        let tree_id = u32::from_le_bytes([data[36], data[37], data[38], data[39]]);
        let session_id = u64::from_le_bytes([
            data[40], data[41], data[42], data[43],
            data[44], data[45], data[46], data[47],
        ]);

        let mut signature = [0u8; 16];
        signature.copy_from_slice(&data[48..64]);

        Some(Smb2Header {
            credit_charge,
            status,
            command,
            credit_request,
            flags,
            next_command,
            message_id,
            process_id,
            tree_id,
            session_id,
            signature,
        })
    }

    /// Parse SMB2 Negotiate request
    fn parse_negotiate_request(&self, data: &[u8]) -> Option<Vec<u16>> {
        if data.len() < 4 {
            return None;
        }

        let dialect_count = u16::from_le_bytes([data[2], data[3]]) as usize;
        let mut dialects = Vec::with_capacity(dialect_count);

        let dialect_offset = 36; // Fixed offset in negotiate request
        if data.len() < dialect_offset + dialect_count * 2 {
            return Some(dialects);
        }

        for i in 0..dialect_count {
            let offset = dialect_offset + i * 2;
            if offset + 2 <= data.len() {
                let dialect = u16::from_le_bytes([data[offset], data[offset + 1]]);
                dialects.push(dialect);
            }
        }

        Some(dialects)
    }

    /// Parse Tree Connect request
    fn parse_tree_connect(&self, data: &[u8], _header: &Smb2Header) -> Option<String> {
        if data.len() < 8 {
            return None;
        }

        let path_offset = u16::from_le_bytes([data[4], data[5]]) as usize;
        let path_length = u16::from_le_bytes([data[6], data[7]]) as usize;

        // Path is relative to SMB2 header start
        let absolute_offset = path_offset.saturating_sub(SMB2_HEADER_SIZE);
        if absolute_offset + path_length > data.len() {
            return None;
        }

        // Path is UTF-16LE encoded
        let path_bytes = &data[absolute_offset..absolute_offset + path_length];
        decode_utf16le(path_bytes)
    }

    /// Parse Create (open file) request
    fn parse_create_request(&self, data: &[u8]) -> Option<(String, u32)> {
        if data.len() < 56 {
            return None;
        }

        let name_offset = u16::from_le_bytes([data[44], data[45]]) as usize;
        let name_length = u16::from_le_bytes([data[46], data[47]]) as usize;
        let desired_access = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);

        let absolute_offset = name_offset.saturating_sub(SMB2_HEADER_SIZE);
        if absolute_offset + name_length > data.len() {
            return None;
        }

        let name_bytes = &data[absolute_offset..absolute_offset + name_length];
        let filename = decode_utf16le(name_bytes)?;

        Some((filename, desired_access))
    }

    /// Parse Session Setup for NTLMSSP
    fn parse_session_setup(&self, data: &[u8]) -> Option<NtlmsspData> {
        if data.len() < 24 {
            return None;
        }

        let blob_offset = u16::from_le_bytes([data[12], data[13]]) as usize;
        let blob_length = u16::from_le_bytes([data[14], data[15]]) as usize;

        let absolute_offset = blob_offset.saturating_sub(SMB2_HEADER_SIZE);
        if absolute_offset + blob_length > data.len() {
            return None;
        }

        let blob = &data[absolute_offset..absolute_offset + blob_length];
        self.parse_ntlmssp(blob)
    }

    /// Parse NTLMSSP authentication blob
    fn parse_ntlmssp(&self, data: &[u8]) -> Option<NtlmsspData> {
        // Look for NTLMSSP signature
        const NTLMSSP_SIG: &[u8] = b"NTLMSSP\x00";

        let sig_pos = data.windows(8).position(|w| w == NTLMSSP_SIG)?;
        let ntlm_data = &data[sig_pos..];

        if ntlm_data.len() < 12 {
            return None;
        }

        let message_type = u32::from_le_bytes([
            ntlm_data[8], ntlm_data[9], ntlm_data[10], ntlm_data[11]
        ]);

        let mut result = NtlmsspData {
            message_type,
            ..Default::default()
        };

        // Type 3 (Auth) message has user/domain info
        if message_type == 3 && ntlm_data.len() >= 88 {
            // Domain
            let domain_len = u16::from_le_bytes([ntlm_data[28], ntlm_data[29]]) as usize;
            let domain_off = u32::from_le_bytes([
                ntlm_data[32], ntlm_data[33], ntlm_data[34], ntlm_data[35]
            ]) as usize;

            if domain_off + domain_len <= ntlm_data.len() {
                result.domain = decode_utf16le(&ntlm_data[domain_off..domain_off + domain_len]);
            }

            // Username
            let user_len = u16::from_le_bytes([ntlm_data[36], ntlm_data[37]]) as usize;
            let user_off = u32::from_le_bytes([
                ntlm_data[40], ntlm_data[41], ntlm_data[42], ntlm_data[43]
            ]) as usize;

            if user_off + user_len <= ntlm_data.len() {
                result.username = decode_utf16le(&ntlm_data[user_off..user_off + user_len]);
            }

            // Workstation
            let ws_len = u16::from_le_bytes([ntlm_data[44], ntlm_data[45]]) as usize;
            let ws_off = u32::from_le_bytes([
                ntlm_data[48], ntlm_data[49], ntlm_data[50], ntlm_data[51]
            ]) as usize;

            if ws_off + ws_len <= ntlm_data.len() {
                result.workstation = decode_utf16le(&ntlm_data[ws_off..ws_off + ws_len]);
            }
        }

        Some(result)
    }

    /// Process SMB1 message
    fn process_smb1(
        &self,
        header: Smb1Header,
        _data: &[u8],
        pstate: &mut ProtocolState,
        _is_request: bool,
    ) -> ParseResult {
        // Get or create SMB-specific state
        let state = if let Some(s) = pstate.get_inner_mut::<SmbState>() {
            s
        } else {
            pstate.set_inner(SmbState::new());
            pstate.get_inner_mut::<SmbState>().unwrap()
        };

        state.set_version(SmbVersion::Smb1);

        let tx = Transaction::new(pstate.current_tx_id() + 1, format!("smb1_{:?}", header.command))
            .with_metadata("command", format!("{:?}", header.command))
            .with_metadata("status", format!("{:#x}", header.status))
            .complete();

        ParseResult::Complete(tx)
    }

    /// Process SMB2/3 message
    fn process_smb2(
        &mut self,
        header: Smb2Header,
        data: &[u8],
        pstate: &mut ProtocolState,
        is_request: bool,
    ) -> ParseResult {
        // Ensure SMB state exists
        if pstate.get_inner::<SmbState>().is_none() {
            pstate.set_inner(SmbState::new());
        }

        // Body starts after header
        let body = if data.len() > SMB2_HEADER_SIZE {
            &data[SMB2_HEADER_SIZE..]
        } else {
            &[]
        };

        let command_type = SmbCommandType::from(header.command);

        // Phase 1: Parse and extract data, set buffers (doesn't need mutable inner state)
        // Also collect data needed for state updates
        let mut tree_connect_info: Option<(u32, String, ShareType)> = None;
        let mut negotiate_response: Option<SmbDialect> = None;
        let mut session_setup_ntlmssp: Option<NtlmsspData> = None;
        let mut session_response_status: Option<(bool, bool)> = None; // (is_failure, is_success)

        match header.command {
            Smb2Command::Negotiate => {
                if is_request {
                    // Parse dialects
                    if let Some(dialects) = self.parse_negotiate_request(body) {
                        pstate.set_buffer("smb.dialects",
                            dialects.iter().flat_map(|d| d.to_le_bytes()).collect());
                    }
                } else {
                    // Parse response to get version - need state for this
                    // We'll handle this in phase 2
                    if body.len() >= 64 {
                        let dialect_revision = u16::from_le_bytes([body[4], body[5]]);
                        let security_mode = u16::from_le_bytes([body[2], body[3]]);
                        let capabilities = u32::from_le_bytes([body[8], body[9], body[10], body[11]]);

                        let version = match dialect_revision {
                            0x0202 => SmbVersion::Smb2_0,
                            0x0210 => SmbVersion::Smb2_1,
                            0x0300 => SmbVersion::Smb3_0,
                            0x0302 => SmbVersion::Smb3_0_2,
                            0x0311 => SmbVersion::Smb3_1_1,
                            _ => SmbVersion::Unknown,
                        };

                        negotiate_response = Some(SmbDialect {
                            version,
                            dialect_revision,
                            capabilities,
                            security_mode,
                        });

                        pstate.set_buffer("smb.version", format!("{:?}", version).into_bytes());
                    }
                }
            }

            Smb2Command::SessionSetup => {
                if is_request {
                    if let Some(ntlmssp) = self.parse_session_setup(body) {
                        if let Some(ref user) = ntlmssp.username {
                            pstate.set_buffer("smb.ntlmssp_user", user.as_bytes().to_vec());
                        }
                        if let Some(ref domain) = ntlmssp.domain {
                            pstate.set_buffer("smb.ntlmssp_domain", domain.as_bytes().to_vec());
                        }
                        session_setup_ntlmssp = Some(ntlmssp);
                    }
                } else {
                    // Record status for phase 2
                    session_response_status = Some((
                        header.status.is_auth_failure(),
                        header.status.is_success(),
                    ));
                }
            }

            Smb2Command::TreeConnect => {
                if is_request {
                    if let Some(path) = self.parse_tree_connect(body, &header) {
                        pstate.set_buffer("smb.share", path.as_bytes().to_vec());
                    }
                } else if header.status.is_success() {
                    // Get share name from buffer before we get mutable inner state
                    if let Some(share) = pstate.get_buffer("smb.share") {
                        if let Ok(share_name) = String::from_utf8(share.to_vec()) {
                            let share_type = if body.len() >= 8 {
                                ShareType::from(body[4])
                            } else {
                                ShareType::Unknown
                            };
                            tree_connect_info = Some((header.tree_id, share_name, share_type));
                        }
                    }
                }
            }

            Smb2Command::Create => {
                if is_request {
                    if let Some((filename, _access_mask)) = self.parse_create_request(body) {
                        pstate.set_buffer("smb.filename", filename.as_bytes().to_vec());

                        // Check if this is a named pipe
                        if filename.to_lowercase().starts_with("\\pipe\\") ||
                           filename.to_lowercase().contains("\\pipe\\") {
                            pstate.set_buffer("smb.named_pipe", filename.as_bytes().to_vec());
                        }
                    }
                }
            }

            Smb2Command::Write | Smb2Command::Read => {
                pstate.set_buffer("smb.command", format!("{:?}", header.command).into_bytes());
            }

            Smb2Command::Ioctl => {
                if body.len() >= 4 {
                    let ctl_code = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
                    pstate.set_buffer("smb.ioctl", ctl_code.to_le_bytes().to_vec());
                }
            }

            _ => {}
        }

        // Set status buffer
        pstate.set_buffer("smb.status", (header.status as u32).to_le_bytes().to_vec());

        // Phase 2: Update mutable SMB state
        if let Some(state) = pstate.get_inner_mut::<SmbState>() {
            state.last_message_id = header.message_id;

            // Apply negotiate response
            if let Some(ref dialect) = negotiate_response {
                state.set_version(dialect.version);
                state.signing = (dialect.security_mode & 0x0002) != 0;
                if dialect.version.supports_encryption() && (dialect.capabilities & 0x00000040) != 0 {
                    state.encrypted = true;
                }
            }

            // Apply session setup
            if let Some(ntlmssp) = session_setup_ntlmssp {
                state.ntlmssp = Some(ntlmssp);
            }

            // Apply session response
            if let Some((is_failure, is_success)) = session_response_status {
                if is_failure {
                    state.record_auth_failure();
                } else if is_success {
                    if let Some(ref ntlmssp) = state.ntlmssp {
                        if let Some(ref user) = ntlmssp.username {
                            state.record_auth_success(user.clone(), ntlmssp.domain.clone());
                        }
                    }
                }
            }

            // Apply tree connect
            if let Some((tree_id, share_name, share_type)) = tree_connect_info {
                state.add_tree(tree_id, share_name, share_type);
            }
        }

        let tx = Transaction::new(pstate.current_tx_id() + 1, format!("{:?}", command_type))
            .with_metadata("command", format!("{:?}", header.command))
            .with_metadata("status", format!("{:?}", header.status))
            .with_metadata("message_id", header.message_id.to_string())
            .with_metadata("session_id", header.session_id.to_string())
            .with_metadata("tree_id", header.tree_id.to_string())
            .complete();

        ParseResult::Complete(tx)
    }
}

impl Default for SmbParser {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProtocolParser for SmbParser {
    fn name(&self) -> &'static str {
        "smb"
    }

    fn protocol(&self) -> Protocol {
        Protocol::Smb
    }

    fn default_tcp_ports(&self) -> &'static [u16] {
        &[445, 139]
    }

    fn default_udp_ports(&self) -> &'static [u16] {
        &[]
    }

    fn probe(&self, payload: &[u8], _direction: Direction) -> u8 {
        // Check for NetBIOS + SMB
        if payload.len() >= NETBIOS_HEADER_SIZE {
            let smb_data = &payload[NETBIOS_HEADER_SIZE..];

            if Self::is_smb2(smb_data) {
                return 100; // Definite SMB2/3
            }
            if Self::is_smb1(smb_data) {
                return 100; // Definite SMB1
            }
        }

        // Check without NetBIOS header (direct TCP)
        if Self::is_smb2(payload) || Self::is_smb1(payload) {
            return 100;
        }

        0
    }

    async fn parse(
        &mut self,
        analysis: &PacketAnalysis,
        state: &mut ProtocolState,
    ) -> ParseResult {
        let payload = analysis.packet.payload();

        if payload.is_empty() {
            return ParseResult::Incomplete;
        }

        // Skip NetBIOS header if present
        let (smb_data, _nb_length) = if payload.len() >= NETBIOS_HEADER_SIZE {
            if let Some((msg_type, length)) = Self::parse_netbios_header(payload) {
                // Session message
                if msg_type == 0x00 {
                    (&payload[NETBIOS_HEADER_SIZE..], Some(length))
                } else {
                    (payload, None)
                }
            } else {
                (payload, None)
            }
        } else {
            (payload, None)
        };

        if smb_data.len() < 4 {
            return ParseResult::Incomplete;
        }

        // Determine request vs response from direction
        let is_request = matches!(analysis.packet.direction, Direction::ToServer);

        // Parse based on SMB version
        if Self::is_smb2(smb_data) {
            if let Some(header) = Self::parse_smb2_header(smb_data) {
                state.detected = true;
                state.protocol = Some(Protocol::Smb);

                // Track bytes
                if is_request {
                    state.bytes_to_server += smb_data.len() as u64;
                } else {
                    state.bytes_to_client += smb_data.len() as u64;
                }

                return self.process_smb2(header, smb_data, state, is_request);
            }
        } else if Self::is_smb1(smb_data) {
            if let Some(header) = Self::parse_smb1_header(smb_data) {
                state.detected = true;
                state.protocol = Some(Protocol::Smb);

                // Track bytes
                if is_request {
                    state.bytes_to_server += smb_data.len() as u64;
                } else {
                    state.bytes_to_client += smb_data.len() as u64;
                }

                return self.process_smb1(header, smb_data, state, is_request);
            }
        }

        ParseResult::NotThisProtocol
    }

    fn match_rules(
        &self,
        state: &ProtocolState,
        rules: &ProtocolRuleSet<'_>,
    ) -> Vec<ProtocolAlert> {
        self.matcher.match_rules(state, rules)
    }

    fn get_buffer<'a>(&self, name: &str, state: &'a ProtocolState) -> Option<&'a [u8]> {
        state.get_buffer(name)
    }

    fn buffer_names(&self) -> &'static [&'static str] {
        &[
            "smb.share",
            "smb.named_pipe",
            "smb.command",
            "smb.status",
            "smb.filename",
            "smb.version",
            "smb.ntlmssp_user",
            "smb.ntlmssp_domain",
            "smb.dialects",
            "smb.ioctl",
        ]
    }

    fn reset(&mut self) {
        // Parser is stateless, state is in ProtocolState
    }
}

/// Decode UTF-16LE to String
fn decode_utf16le(data: &[u8]) -> Option<String> {
    if data.len() % 2 != 0 {
        return None;
    }

    let u16_chars: Vec<u16> = data
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();

    String::from_utf16(&u16_chars).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_smb2() {
        let parser = SmbParser::new();

        // SMB2 magic
        let smb2_data = b"\xFESMB\x00\x00\x00\x00";
        assert_eq!(parser.probe(smb2_data, Direction::ToServer), 100);

        // With NetBIOS header
        let netbios_smb2 = b"\x00\x00\x00\x04\xFESMB";
        assert_eq!(parser.probe(netbios_smb2, Direction::ToServer), 100);
    }

    #[test]
    fn test_probe_smb1() {
        let parser = SmbParser::new();

        // SMB1 magic
        let smb1_data = b"\xFFSMB\x72\x00\x00\x00";
        assert_eq!(parser.probe(smb1_data, Direction::ToServer), 100);
    }

    #[test]
    fn test_decode_utf16le() {
        let utf16 = b"T\x00e\x00s\x00t\x00";
        assert_eq!(decode_utf16le(utf16), Some("Test".to_string()));
    }

    #[test]
    fn test_smb2_header_parse() {
        let mut header_data = vec![0u8; 64];
        // Magic
        header_data[0..4].copy_from_slice(b"\xFESMB");
        // Structure size
        header_data[4..6].copy_from_slice(&64u16.to_le_bytes());
        // Command = TreeConnect (3)
        header_data[12..14].copy_from_slice(&3u16.to_le_bytes());

        let header = SmbParser::parse_smb2_header(&header_data).unwrap();
        assert_eq!(header.command, Smb2Command::TreeConnect);
    }
}
