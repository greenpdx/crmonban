//! 802.11 Data Frame Types
//!
//! Data frames for actual data transmission.

/// Data frame
#[derive(Debug, Clone)]
pub struct DataFrame {
    /// Is encrypted (protected)
    pub encrypted: bool,
    /// LLC/SNAP header if present
    pub llc: Option<LlcSnapHeader>,
    /// EAPOL frame if present (for WPA handshake)
    pub eapol: Option<EapolFrame>,
    /// Payload data
    pub payload: Vec<u8>,
}

impl DataFrame {
    pub fn parse(data: &[u8], protected: bool) -> Option<Self> {
        let mut frame = DataFrame {
            encrypted: protected,
            llc: None,
            eapol: None,
            payload: data.to_vec(),
        };

        // If not encrypted, try to parse LLC/SNAP header
        if !protected && data.len() >= 8 {
            if let Some(llc) = LlcSnapHeader::parse(data) {
                frame.llc = Some(llc.clone());

                // Check for EAPOL (EtherType 0x888e)
                if llc.ethertype == 0x888e && data.len() > 8 {
                    frame.eapol = EapolFrame::parse(&data[8..]);
                }
            }
        }

        Some(frame)
    }

    /// Check if this contains an EAPOL frame
    pub fn has_eapol(&self) -> bool {
        self.eapol.is_some()
    }
}

/// LLC/SNAP header
#[derive(Debug, Clone)]
pub struct LlcSnapHeader {
    /// Destination SAP (usually 0xAA for SNAP)
    pub dsap: u8,
    /// Source SAP (usually 0xAA for SNAP)
    pub ssap: u8,
    /// Control field
    pub control: u8,
    /// OUI (usually 00:00:00 for Ethernet)
    pub oui: [u8; 3],
    /// EtherType
    pub ethertype: u16,
}

impl LlcSnapHeader {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }

        let dsap = data[0];
        let ssap = data[1];
        let control = data[2];

        // Check for SNAP (0xAA, 0xAA, 0x03)
        if dsap != 0xaa || ssap != 0xaa || control != 0x03 {
            return None;
        }

        let mut oui = [0u8; 3];
        oui.copy_from_slice(&data[3..6]);

        let ethertype = u16::from_be_bytes([data[6], data[7]]);

        Some(LlcSnapHeader {
            dsap,
            ssap,
            control,
            oui,
            ethertype,
        })
    }
}

/// EAPOL (Extensible Authentication Protocol over LAN) frame
#[derive(Debug, Clone)]
pub struct EapolFrame {
    /// Protocol version
    pub version: u8,
    /// Packet type
    pub packet_type: EapolType,
    /// Body length
    pub body_length: u16,
    /// EAPOL-Key data (if Key type)
    pub key_data: Option<EapolKeyData>,
    /// Raw body
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapolType {
    Packet,
    Start,
    Logoff,
    Key,
    AsfAlert,
    MkaPdu,
    Unknown(u8),
}

impl From<u8> for EapolType {
    fn from(val: u8) -> Self {
        match val {
            0 => EapolType::Packet,
            1 => EapolType::Start,
            2 => EapolType::Logoff,
            3 => EapolType::Key,
            4 => EapolType::AsfAlert,
            5 => EapolType::MkaPdu,
            _ => EapolType::Unknown(val),
        }
    }
}

impl EapolFrame {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }

        let version = data[0];
        let packet_type = EapolType::from(data[1]);
        let body_length = u16::from_be_bytes([data[2], data[3]]);

        let body = if data.len() > 4 {
            data[4..].to_vec()
        } else {
            Vec::new()
        };

        let key_data = if packet_type == EapolType::Key && body.len() >= 77 {
            EapolKeyData::parse(&body)
        } else {
            None
        };

        Some(EapolFrame {
            version,
            packet_type,
            body_length,
            key_data,
            body,
        })
    }

    /// Check if this is an EAPOL-Key frame (WPA handshake)
    pub fn is_key(&self) -> bool {
        self.packet_type == EapolType::Key
    }

    /// Check if this is an EAPOL-Start
    pub fn is_start(&self) -> bool {
        self.packet_type == EapolType::Start
    }
}

/// EAPOL-Key data (for 4-way handshake)
#[derive(Debug, Clone)]
pub struct EapolKeyData {
    /// Descriptor type (1=RC4, 2=RSN/WPA2)
    pub descriptor_type: u8,
    /// Key information
    pub key_info: KeyInfo,
    /// Key length
    pub key_length: u16,
    /// Replay counter
    pub replay_counter: u64,
    /// Key nonce
    pub nonce: [u8; 32],
    /// Key IV
    pub iv: [u8; 16],
    /// Key RSC
    pub rsc: [u8; 8],
    /// Key ID
    pub key_id: [u8; 8],
    /// Key MIC
    pub mic: [u8; 16],
    /// Key data length
    pub data_length: u16,
    /// Key data
    pub data: Vec<u8>,
}

/// Key information flags
#[derive(Debug, Clone, Copy)]
pub struct KeyInfo {
    /// Key descriptor version (1=HMAC-MD5-RC4, 2=HMAC-SHA1-AES, 3=AES-128-CMAC)
    pub version: u8,
    /// Key type (0=Group, 1=Pairwise)
    pub key_type: bool,
    /// Key index (for group keys)
    pub key_index: u8,
    /// Install flag
    pub install: bool,
    /// Key ACK
    pub ack: bool,
    /// Key MIC present
    pub mic: bool,
    /// Secure flag
    pub secure: bool,
    /// Error flag
    pub error: bool,
    /// Request flag
    pub request: bool,
    /// Encrypted key data
    pub encrypted: bool,
    /// SMK message
    pub smk: bool,
}

impl KeyInfo {
    pub fn from_u16(val: u16) -> Self {
        KeyInfo {
            version: (val & 0x07) as u8,
            key_type: val & 0x08 != 0,
            key_index: ((val >> 4) & 0x03) as u8,
            install: val & 0x40 != 0,
            ack: val & 0x80 != 0,
            mic: val & 0x100 != 0,
            secure: val & 0x200 != 0,
            error: val & 0x400 != 0,
            request: val & 0x800 != 0,
            encrypted: val & 0x1000 != 0,
            smk: val & 0x2000 != 0,
        }
    }

    /// Get handshake message number (1-4)
    pub fn message_number(&self) -> u8 {
        match (self.ack, self.mic, self.secure, self.install) {
            (true, false, false, false) => 1,  // AP -> STA, ANonce
            (false, true, false, false) => 2,  // STA -> AP, SNonce
            (true, true, true, true) => 3,     // AP -> STA, install key
            (false, true, true, false) => 4,   // STA -> AP, confirm
            _ => 0,
        }
    }
}

impl EapolKeyData {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 77 {
            return None;
        }

        let descriptor_type = data[0];
        let key_info = KeyInfo::from_u16(u16::from_be_bytes([data[1], data[2]]));
        let key_length = u16::from_be_bytes([data[3], data[4]]);

        let replay_counter = u64::from_be_bytes([
            data[5], data[6], data[7], data[8],
            data[9], data[10], data[11], data[12],
        ]);

        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&data[13..45]);

        let mut iv = [0u8; 16];
        iv.copy_from_slice(&data[45..61]);

        let mut rsc = [0u8; 8];
        rsc.copy_from_slice(&data[61..69]);

        let mut key_id = [0u8; 8];
        key_id.copy_from_slice(&data[69..77]);

        let mut mic = [0u8; 16];
        if data.len() >= 93 {
            mic.copy_from_slice(&data[77..93]);
        }

        let data_length = if data.len() >= 95 {
            u16::from_be_bytes([data[93], data[94]])
        } else {
            0
        };

        let key_data = if data.len() > 95 {
            data[95..].to_vec()
        } else {
            Vec::new()
        };

        Some(EapolKeyData {
            descriptor_type,
            key_info,
            key_length,
            replay_counter,
            nonce,
            iv,
            rsc,
            key_id,
            mic,
            data_length,
            data: key_data,
        })
    }

    /// Check if this contains PMKID (in message 1)
    pub fn has_pmkid(&self) -> bool {
        // PMKID is in key data of message 1, tag 0xdd with OUI 00:0f:ac:04
        if self.key_info.message_number() == 1 && self.data.len() >= 22 {
            // Look for PMKID KDE
            let mut pos = 0;
            while pos + 2 < self.data.len() {
                let tag = self.data[pos];
                let len = self.data[pos + 1] as usize;
                if tag == 0xdd && len >= 20 && pos + 2 + len <= self.data.len() {
                    // Check OUI 00:0f:ac and type 04 (PMKID)
                    if self.data[pos + 2..pos + 5] == [0x00, 0x0f, 0xac] && self.data[pos + 5] == 0x04 {
                        return true;
                    }
                }
                pos += 2 + len;
            }
        }
        false
    }

    /// Get handshake message number
    pub fn message_number(&self) -> u8 {
        self.key_info.message_number()
    }
}
