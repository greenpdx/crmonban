//! 802.11 Management Frame Types
//!
//! Parses management frames: Beacon, Probe Request/Response, Auth, Deauth, etc.

use super::frame::FrameSubtype;

/// Management frame variants
#[derive(Debug, Clone)]
pub enum ManagementFrame {
    Beacon(BeaconFrame),
    ProbeRequest(ProbeRequest),
    ProbeResponse(ProbeResponse),
    Authentication(AuthFrame),
    Deauthentication(DeauthFrame),
    Association(AssocFrame),
    Disassociation(DisassocFrame),
    Reassociation(ReassocFrame),
    Action(ActionFrame),
    Unknown(Vec<u8>),
}

impl ManagementFrame {
    pub fn parse(subtype: FrameSubtype, data: &[u8]) -> Option<Self> {
        match subtype {
            FrameSubtype::Beacon => BeaconFrame::parse(data).map(ManagementFrame::Beacon),
            FrameSubtype::ProbeRequest => ProbeRequest::parse(data).map(ManagementFrame::ProbeRequest),
            FrameSubtype::ProbeResponse => ProbeResponse::parse(data).map(ManagementFrame::ProbeResponse),
            FrameSubtype::Authentication => AuthFrame::parse(data).map(ManagementFrame::Authentication),
            FrameSubtype::Deauthentication => DeauthFrame::parse(data).map(ManagementFrame::Deauthentication),
            FrameSubtype::AssocRequest | FrameSubtype::AssocResponse => AssocFrame::parse(data).map(ManagementFrame::Association),
            FrameSubtype::Disassociation => DisassocFrame::parse(data).map(ManagementFrame::Disassociation),
            FrameSubtype::ReassocRequest | FrameSubtype::ReassocResponse => ReassocFrame::parse(data).map(ManagementFrame::Reassociation),
            FrameSubtype::Action | FrameSubtype::ActionNoAck => ActionFrame::parse(data).map(ManagementFrame::Action),
            _ => Some(ManagementFrame::Unknown(data.to_vec())),
        }
    }
}

/// Information Element (IE) types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ElementId {
    Ssid = 0,
    SupportedRates = 1,
    DsParameter = 3,
    Tim = 5,
    Country = 7,
    HtCapabilities = 45,
    RsnInfo = 48,
    ExtendedSupportedRates = 50,
    HtOperation = 61,
    VhtCapabilities = 191,
    VhtOperation = 192,
    VendorSpecific = 221,
    Unknown = 255,
}

impl From<u8> for ElementId {
    fn from(val: u8) -> Self {
        match val {
            0 => ElementId::Ssid,
            1 => ElementId::SupportedRates,
            3 => ElementId::DsParameter,
            5 => ElementId::Tim,
            7 => ElementId::Country,
            45 => ElementId::HtCapabilities,
            48 => ElementId::RsnInfo,
            50 => ElementId::ExtendedSupportedRates,
            61 => ElementId::HtOperation,
            191 => ElementId::VhtCapabilities,
            192 => ElementId::VhtOperation,
            221 => ElementId::VendorSpecific,
            _ => ElementId::Unknown,
        }
    }
}

/// Parsed Information Element
#[derive(Debug, Clone)]
pub struct InformationElement {
    pub id: ElementId,
    pub raw_id: u8,
    pub data: Vec<u8>,
}

/// Parse information elements from management frame body
pub fn parse_ies(data: &[u8]) -> Vec<InformationElement> {
    let mut ies = Vec::new();
    let mut pos = 0;

    while pos + 2 <= data.len() {
        let id = data[pos];
        let len = data[pos + 1] as usize;
        pos += 2;

        if pos + len > data.len() {
            break;
        }

        ies.push(InformationElement {
            id: ElementId::from(id),
            raw_id: id,
            data: data[pos..pos + len].to_vec(),
        });

        pos += len;
    }

    ies
}

/// RSN (Robust Security Network) Information
#[derive(Debug, Clone, Default)]
pub struct RsnInfo {
    pub version: u16,
    pub group_cipher: CipherSuite,
    pub pairwise_ciphers: Vec<CipherSuite>,
    pub auth_key_mgmt: Vec<AkmSuite>,
    pub capabilities: u16,
    pub pmkid_count: u16,
    pub pmkids: Vec<[u8; 16]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CipherSuite {
    #[default]
    None,
    Wep40,
    Tkip,
    Reserved,
    Ccmp,
    Wep104,
    BipCmac128,
    Gcmp128,
    Gcmp256,
    Ccmp256,
    BipGmac128,
    BipGmac256,
    Unknown(u8),
}

impl From<u8> for CipherSuite {
    fn from(val: u8) -> Self {
        match val {
            0 => CipherSuite::None,
            1 => CipherSuite::Wep40,
            2 => CipherSuite::Tkip,
            3 => CipherSuite::Reserved,
            4 => CipherSuite::Ccmp,
            5 => CipherSuite::Wep104,
            6 => CipherSuite::BipCmac128,
            8 => CipherSuite::Gcmp128,
            9 => CipherSuite::Gcmp256,
            10 => CipherSuite::Ccmp256,
            11 => CipherSuite::BipGmac128,
            12 => CipherSuite::BipGmac256,
            _ => CipherSuite::Unknown(val),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AkmSuite {
    #[default]
    None,
    Dot1x,
    Psk,
    Ft8021x,
    FtPsk,
    Dot1xSha256,
    PskSha256,
    Sae,
    FtSae,
    Owe,
    Unknown(u8),
}

impl From<u8> for AkmSuite {
    fn from(val: u8) -> Self {
        match val {
            0 => AkmSuite::None,
            1 => AkmSuite::Dot1x,
            2 => AkmSuite::Psk,
            3 => AkmSuite::Ft8021x,
            4 => AkmSuite::FtPsk,
            5 => AkmSuite::Dot1xSha256,
            6 => AkmSuite::PskSha256,
            8 => AkmSuite::Sae,
            9 => AkmSuite::FtSae,
            18 => AkmSuite::Owe,
            _ => AkmSuite::Unknown(val),
        }
    }
}

impl RsnInfo {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }

        let mut rsn = RsnInfo::default();
        rsn.version = u16::from_le_bytes([data[0], data[1]]);

        // Group cipher suite (4 bytes: 3 OUI + 1 type)
        if data.len() >= 6 {
            rsn.group_cipher = CipherSuite::from(data[5]);
        }

        let mut pos = 6;

        // Pairwise cipher suites
        if pos + 2 <= data.len() {
            let count = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;

            for _ in 0..count {
                if pos + 4 <= data.len() {
                    rsn.pairwise_ciphers.push(CipherSuite::from(data[pos + 3]));
                    pos += 4;
                }
            }
        }

        // AKM suites
        if pos + 2 <= data.len() {
            let count = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;

            for _ in 0..count {
                if pos + 4 <= data.len() {
                    rsn.auth_key_mgmt.push(AkmSuite::from(data[pos + 3]));
                    pos += 4;
                }
            }
        }

        // RSN capabilities
        if pos + 2 <= data.len() {
            rsn.capabilities = u16::from_le_bytes([data[pos], data[pos + 1]]);
            pos += 2;
        }

        // PMKID count and PMKIDs
        if pos + 2 <= data.len() {
            rsn.pmkid_count = u16::from_le_bytes([data[pos], data[pos + 1]]);
            pos += 2;

            for _ in 0..rsn.pmkid_count {
                if pos + 16 <= data.len() {
                    let mut pmkid = [0u8; 16];
                    pmkid.copy_from_slice(&data[pos..pos + 16]);
                    rsn.pmkids.push(pmkid);
                    pos += 16;
                }
            }
        }

        Some(rsn)
    }

    /// Check if WPA3 (SAE) is supported
    pub fn is_wpa3(&self) -> bool {
        self.auth_key_mgmt.iter().any(|a| matches!(a, AkmSuite::Sae | AkmSuite::FtSae))
    }

    /// Check if WPA2 (CCMP/PSK or 802.1X) is used
    pub fn is_wpa2(&self) -> bool {
        self.pairwise_ciphers.iter().any(|c| matches!(c, CipherSuite::Ccmp | CipherSuite::Gcmp128 | CipherSuite::Gcmp256))
    }
}

/// Beacon frame
#[derive(Debug, Clone)]
pub struct BeaconFrame {
    /// Timestamp (microseconds)
    pub timestamp: u64,
    /// Beacon interval (TUs, 1 TU = 1024 microseconds)
    pub interval: u16,
    /// Capability information
    pub capability: u16,
    /// SSID
    pub ssid: String,
    /// Current channel
    pub channel: Option<u8>,
    /// Supported rates
    pub rates: Vec<u8>,
    /// RSN information (WPA2/WPA3)
    pub rsn: Option<RsnInfo>,
    /// Raw information elements
    pub ies: Vec<InformationElement>,
}

impl BeaconFrame {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 12 {
            return None;
        }

        let timestamp = u64::from_le_bytes([
            data[0], data[1], data[2], data[3],
            data[4], data[5], data[6], data[7],
        ]);
        let interval = u16::from_le_bytes([data[8], data[9]]);
        let capability = u16::from_le_bytes([data[10], data[11]]);

        let ies = parse_ies(&data[12..]);

        let mut beacon = BeaconFrame {
            timestamp,
            interval,
            capability,
            ssid: String::new(),
            channel: None,
            rates: Vec::new(),
            rsn: None,
            ies: ies.clone(),
        };

        // Extract common IEs
        for ie in &ies {
            match ie.id {
                ElementId::Ssid => {
                    beacon.ssid = String::from_utf8_lossy(&ie.data).to_string();
                }
                ElementId::DsParameter if !ie.data.is_empty() => {
                    beacon.channel = Some(ie.data[0]);
                }
                ElementId::SupportedRates | ElementId::ExtendedSupportedRates => {
                    beacon.rates.extend(&ie.data);
                }
                ElementId::RsnInfo => {
                    beacon.rsn = RsnInfo::parse(&ie.data);
                }
                _ => {}
            }
        }

        Some(beacon)
    }

    /// Check if this is an ESS (infrastructure) BSS
    pub fn is_ess(&self) -> bool {
        self.capability & 0x0001 != 0
    }

    /// Check if this is an IBSS (ad-hoc)
    pub fn is_ibss(&self) -> bool {
        self.capability & 0x0002 != 0
    }

    /// Check if privacy (encryption) is required
    pub fn is_privacy(&self) -> bool {
        self.capability & 0x0010 != 0
    }
}

/// Probe request frame
#[derive(Debug, Clone)]
pub struct ProbeRequest {
    /// SSID (empty for broadcast probe)
    pub ssid: String,
    /// Supported rates
    pub rates: Vec<u8>,
    /// Raw information elements
    pub ies: Vec<InformationElement>,
}

impl ProbeRequest {
    pub fn parse(data: &[u8]) -> Option<Self> {
        let ies = parse_ies(data);

        let mut probe = ProbeRequest {
            ssid: String::new(),
            rates: Vec::new(),
            ies: ies.clone(),
        };

        for ie in &ies {
            match ie.id {
                ElementId::Ssid => {
                    probe.ssid = String::from_utf8_lossy(&ie.data).to_string();
                }
                ElementId::SupportedRates | ElementId::ExtendedSupportedRates => {
                    probe.rates.extend(&ie.data);
                }
                _ => {}
            }
        }

        Some(probe)
    }

    /// Check if this is a broadcast probe (any SSID)
    pub fn is_broadcast(&self) -> bool {
        self.ssid.is_empty()
    }
}

/// Probe response frame
#[derive(Debug, Clone)]
pub struct ProbeResponse {
    /// Same structure as beacon
    pub timestamp: u64,
    pub interval: u16,
    pub capability: u16,
    pub ssid: String,
    pub channel: Option<u8>,
    pub rates: Vec<u8>,
    pub rsn: Option<RsnInfo>,
    pub ies: Vec<InformationElement>,
}

impl ProbeResponse {
    pub fn parse(data: &[u8]) -> Option<Self> {
        // Probe response has same format as beacon
        let beacon = BeaconFrame::parse(data)?;
        Some(ProbeResponse {
            timestamp: beacon.timestamp,
            interval: beacon.interval,
            capability: beacon.capability,
            ssid: beacon.ssid,
            channel: beacon.channel,
            rates: beacon.rates,
            rsn: beacon.rsn,
            ies: beacon.ies,
        })
    }
}

/// Authentication frame
#[derive(Debug, Clone)]
pub struct AuthFrame {
    /// Authentication algorithm (0=Open, 1=Shared Key, 3=SAE)
    pub algorithm: u16,
    /// Sequence number
    pub seq_num: u16,
    /// Status code
    pub status: u16,
    /// Challenge text (for shared key auth)
    pub challenge: Option<Vec<u8>>,
    /// SAE elements (for WPA3)
    pub sae_elements: Option<Vec<u8>>,
}

impl AuthFrame {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 6 {
            return None;
        }

        let algorithm = u16::from_le_bytes([data[0], data[1]]);
        let seq_num = u16::from_le_bytes([data[2], data[3]]);
        let status = u16::from_le_bytes([data[4], data[5]]);

        let mut auth = AuthFrame {
            algorithm,
            seq_num,
            status,
            challenge: None,
            sae_elements: None,
        };

        // Parse remaining elements based on algorithm
        if data.len() > 6 {
            let remaining = &data[6..];
            if algorithm == 1 {
                // Shared key - challenge text
                auth.challenge = Some(remaining.to_vec());
            } else if algorithm == 3 {
                // SAE
                auth.sae_elements = Some(remaining.to_vec());
            }
        }

        Some(auth)
    }

    /// Check if this is SAE (WPA3)
    pub fn is_sae(&self) -> bool {
        self.algorithm == 3
    }

    /// Check if successful
    pub fn is_success(&self) -> bool {
        self.status == 0
    }
}

/// Deauthentication frame
#[derive(Debug, Clone)]
pub struct DeauthFrame {
    /// Reason code
    pub reason_code: u16,
}

impl DeauthFrame {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 2 {
            return None;
        }

        Some(DeauthFrame {
            reason_code: u16::from_le_bytes([data[0], data[1]]),
        })
    }

    /// Get reason description
    pub fn reason_description(&self) -> &'static str {
        match self.reason_code {
            1 => "Unspecified reason",
            2 => "Previous authentication no longer valid",
            3 => "Leaving BSS (or IBSS)",
            4 => "Disassociated due to inactivity",
            5 => "Disassociated because AP is unable to handle all associated STAs",
            6 => "Class 2 frame received from nonauthenticated STA",
            7 => "Class 3 frame received from nonassociated STA",
            8 => "Disassociated because leaving BSS",
            9 => "STA requesting association not authenticated with responding STA",
            10 => "Disassociated because the info in Power Capability is unacceptable",
            11 => "Disassociated because the info in Supported Channels is unacceptable",
            13 => "Invalid information element",
            14 => "MIC failure",
            15 => "4-Way Handshake timeout",
            16 => "Group Key Handshake timeout",
            17 => "IE in 4-Way Handshake different from association",
            18 => "Invalid group cipher",
            19 => "Invalid pairwise cipher",
            20 => "Invalid AKMP",
            21 => "Unsupported RSN information element version",
            22 => "Invalid RSN information element capabilities",
            23 => "802.1X authentication failed",
            24 => "Cipher suite rejected because of security policy",
            _ => "Unknown reason",
        }
    }
}

/// Disassociation frame
#[derive(Debug, Clone)]
pub struct DisassocFrame {
    /// Reason code (same as deauth)
    pub reason_code: u16,
}

impl DisassocFrame {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 2 {
            return None;
        }

        Some(DisassocFrame {
            reason_code: u16::from_le_bytes([data[0], data[1]]),
        })
    }
}

/// Association request/response frame
#[derive(Debug, Clone)]
pub struct AssocFrame {
    /// Capability information
    pub capability: u16,
    /// Listen interval (request) or Status code (response)
    pub status_or_interval: u16,
    /// Association ID (response only)
    pub aid: Option<u16>,
    /// SSID
    pub ssid: Option<String>,
    /// Supported rates
    pub rates: Vec<u8>,
    /// RSN information
    pub rsn: Option<RsnInfo>,
}

impl AssocFrame {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }

        let capability = u16::from_le_bytes([data[0], data[1]]);
        let status_or_interval = u16::from_le_bytes([data[2], data[3]]);

        // Association response has AID at offset 4
        let (aid, ie_start) = if data.len() >= 6 {
            // Could be response with AID
            (Some(u16::from_le_bytes([data[4], data[5]]) & 0x3fff), 6)
        } else {
            (None, 4)
        };

        let ies = if data.len() > ie_start {
            parse_ies(&data[ie_start..])
        } else {
            Vec::new()
        };

        let mut assoc = AssocFrame {
            capability,
            status_or_interval,
            aid,
            ssid: None,
            rates: Vec::new(),
            rsn: None,
        };

        for ie in &ies {
            match ie.id {
                ElementId::Ssid => {
                    assoc.ssid = Some(String::from_utf8_lossy(&ie.data).to_string());
                }
                ElementId::SupportedRates | ElementId::ExtendedSupportedRates => {
                    assoc.rates.extend(&ie.data);
                }
                ElementId::RsnInfo => {
                    assoc.rsn = RsnInfo::parse(&ie.data);
                }
                _ => {}
            }
        }

        Some(assoc)
    }
}

/// Reassociation frame
#[derive(Debug, Clone)]
pub struct ReassocFrame {
    /// Same fields as association
    pub capability: u16,
    pub status_or_interval: u16,
    /// Current AP address (reassoc request)
    pub current_ap: Option<[u8; 6]>,
}

impl ReassocFrame {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 10 {
            return None;
        }

        let capability = u16::from_le_bytes([data[0], data[1]]);
        let status_or_interval = u16::from_le_bytes([data[2], data[3]]);

        let mut current_ap = [0u8; 6];
        current_ap.copy_from_slice(&data[4..10]);

        Some(ReassocFrame {
            capability,
            status_or_interval,
            current_ap: Some(current_ap),
        })
    }
}

/// Action frame
#[derive(Debug, Clone)]
pub struct ActionFrame {
    /// Action category
    pub category: u8,
    /// Action code
    pub action: u8,
    /// Action-specific data
    pub data: Vec<u8>,
}

impl ActionFrame {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 2 {
            return None;
        }

        Some(ActionFrame {
            category: data[0],
            action: data[1],
            data: data[2..].to_vec(),
        })
    }
}
