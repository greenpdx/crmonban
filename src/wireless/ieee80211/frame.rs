//! 802.11 Frame Structure
//!
//! Defines the main 802.11 frame header and frame control fields.

use super::management::ManagementFrame;
use super::control::ControlFrame;
use super::data::DataFrame;

/// MAC address (6 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr([u8; 6]);

impl MacAddr {
    pub const BROADCAST: MacAddr = MacAddr([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    pub const ZERO: MacAddr = MacAddr([0, 0, 0, 0, 0, 0]);

    pub fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(data: &[u8]) -> Option<Self> {
        if data.len() >= 6 {
            let mut bytes = [0u8; 6];
            bytes.copy_from_slice(&data[..6]);
            Some(Self(bytes))
        } else {
            None
        }
    }

    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }

    pub fn is_broadcast(&self) -> bool {
        self.0 == [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    }

    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    pub fn is_locally_administered(&self) -> bool {
        self.0[0] & 0x02 != 0
    }
}

impl std::fmt::Display for MacAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2],
            self.0[3], self.0[4], self.0[5])
    }
}

/// Frame type (2 bits)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Management = 0,
    Control = 1,
    Data = 2,
    Extension = 3,
}

impl From<u8> for FrameType {
    fn from(val: u8) -> Self {
        match val & 0x03 {
            0 => FrameType::Management,
            1 => FrameType::Control,
            2 => FrameType::Data,
            _ => FrameType::Extension,
        }
    }
}

/// Frame subtype (4 bits)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameSubtype {
    // Management subtypes
    AssocRequest = 0x00,
    AssocResponse = 0x01,
    ReassocRequest = 0x02,
    ReassocResponse = 0x03,
    ProbeRequest = 0x04,
    ProbeResponse = 0x05,
    TimingAdvertisement = 0x06,
    Beacon = 0x08,
    Atim = 0x09,
    Disassociation = 0x0a,
    Authentication = 0x0b,
    Deauthentication = 0x0c,
    Action = 0x0d,
    ActionNoAck = 0x0e,

    // Control subtypes (offset by 0x10 for distinction)
    CtrlWrapper = 0x17,
    BlockAckRequest = 0x18,
    BlockAck = 0x19,
    PsPoll = 0x1a,
    Rts = 0x1b,
    Cts = 0x1c,
    Ack = 0x1d,
    CfEnd = 0x1e,
    CfEndCfAck = 0x1f,

    // Data subtypes (offset by 0x20 for distinction)
    Data = 0x20,
    DataCfAck = 0x21,
    DataCfPoll = 0x22,
    DataCfAckCfPoll = 0x23,
    Null = 0x24,
    NullCfAck = 0x25,
    NullCfPoll = 0x26,
    NullCfAckCfPoll = 0x27,
    QosData = 0x28,
    QosDataCfAck = 0x29,
    QosDataCfPoll = 0x2a,
    QosDataCfAckCfPoll = 0x2b,
    QosNull = 0x2c,
    QosNullCfAck = 0x2d,
    QosNullCfPoll = 0x2e,
    QosNullCfAckCfPoll = 0x2f,

    Unknown = 0xff,
}

impl FrameSubtype {
    pub fn from_raw(frame_type: FrameType, subtype: u8) -> Self {
        let sub = subtype & 0x0f;
        match frame_type {
            FrameType::Management => match sub {
                0 => FrameSubtype::AssocRequest,
                1 => FrameSubtype::AssocResponse,
                2 => FrameSubtype::ReassocRequest,
                3 => FrameSubtype::ReassocResponse,
                4 => FrameSubtype::ProbeRequest,
                5 => FrameSubtype::ProbeResponse,
                6 => FrameSubtype::TimingAdvertisement,
                8 => FrameSubtype::Beacon,
                9 => FrameSubtype::Atim,
                10 => FrameSubtype::Disassociation,
                11 => FrameSubtype::Authentication,
                12 => FrameSubtype::Deauthentication,
                13 => FrameSubtype::Action,
                14 => FrameSubtype::ActionNoAck,
                _ => FrameSubtype::Unknown,
            },
            FrameType::Control => match sub {
                7 => FrameSubtype::CtrlWrapper,
                8 => FrameSubtype::BlockAckRequest,
                9 => FrameSubtype::BlockAck,
                10 => FrameSubtype::PsPoll,
                11 => FrameSubtype::Rts,
                12 => FrameSubtype::Cts,
                13 => FrameSubtype::Ack,
                14 => FrameSubtype::CfEnd,
                15 => FrameSubtype::CfEndCfAck,
                _ => FrameSubtype::Unknown,
            },
            FrameType::Data => match sub {
                0 => FrameSubtype::Data,
                1 => FrameSubtype::DataCfAck,
                2 => FrameSubtype::DataCfPoll,
                3 => FrameSubtype::DataCfAckCfPoll,
                4 => FrameSubtype::Null,
                5 => FrameSubtype::NullCfAck,
                6 => FrameSubtype::NullCfPoll,
                7 => FrameSubtype::NullCfAckCfPoll,
                8 => FrameSubtype::QosData,
                9 => FrameSubtype::QosDataCfAck,
                10 => FrameSubtype::QosDataCfPoll,
                11 => FrameSubtype::QosDataCfAckCfPoll,
                12 => FrameSubtype::QosNull,
                13 => FrameSubtype::QosNullCfAck,
                14 => FrameSubtype::QosNullCfPoll,
                15 => FrameSubtype::QosNullCfAckCfPoll,
                _ => FrameSubtype::Unknown,
            },
            FrameType::Extension => FrameSubtype::Unknown,
        }
    }
}

/// Frame control field (2 bytes)
#[derive(Debug, Clone, Copy)]
pub struct FrameControl {
    /// Protocol version (should be 0)
    pub protocol_version: u8,
    /// Frame type
    pub frame_type: FrameType,
    /// Frame subtype
    pub subtype: FrameSubtype,
    /// To DS flag
    pub to_ds: bool,
    /// From DS flag
    pub from_ds: bool,
    /// More fragments flag
    pub more_fragments: bool,
    /// Retry flag
    pub retry: bool,
    /// Power management flag
    pub power_management: bool,
    /// More data flag
    pub more_data: bool,
    /// Protected frame flag (WEP/WPA)
    pub protected: bool,
    /// HT/VHT order flag
    pub order: bool,
}

impl FrameControl {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 2 {
            return None;
        }

        let fc0 = data[0];
        let fc1 = data[1];

        let protocol_version = fc0 & 0x03;
        let frame_type = FrameType::from((fc0 >> 2) & 0x03);
        let subtype_raw = (fc0 >> 4) & 0x0f;
        let subtype = FrameSubtype::from_raw(frame_type, subtype_raw);

        Some(Self {
            protocol_version,
            frame_type,
            subtype,
            to_ds: fc1 & 0x01 != 0,
            from_ds: fc1 & 0x02 != 0,
            more_fragments: fc1 & 0x04 != 0,
            retry: fc1 & 0x08 != 0,
            power_management: fc1 & 0x10 != 0,
            more_data: fc1 & 0x20 != 0,
            protected: fc1 & 0x40 != 0,
            order: fc1 & 0x80 != 0,
        })
    }
}

/// 802.11 frame
#[derive(Debug, Clone)]
pub struct Ieee80211Frame {
    /// Frame control
    pub frame_control: FrameControl,
    /// Duration/ID
    pub duration: u16,
    /// Address 1 (Receiver/Destination)
    pub addr1: MacAddr,
    /// Address 2 (Transmitter/Source)
    pub addr2: Option<MacAddr>,
    /// Address 3 (BSSID or other)
    pub addr3: Option<MacAddr>,
    /// Sequence control
    pub seq_control: Option<u16>,
    /// Address 4 (for WDS)
    pub addr4: Option<MacAddr>,
    /// QoS control (if QoS data frame)
    pub qos_control: Option<u16>,
    /// Frame body
    pub body: FrameBody,
}

/// Frame body variants
#[derive(Debug, Clone)]
pub enum FrameBody {
    Management(ManagementFrame),
    Control(ControlFrame),
    Data(DataFrame),
    Unknown(Vec<u8>),
}

impl Ieee80211Frame {
    /// Parse an 802.11 frame
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 10 {
            return None;
        }

        let frame_control = FrameControl::parse(data)?;
        let duration = u16::from_le_bytes([data[2], data[3]]);
        let addr1 = MacAddr::from_slice(&data[4..])?;

        // Minimum header size depends on frame type
        let (addr2, addr3, seq_control, addr4, qos_control, body_offset) =
            match frame_control.frame_type {
                FrameType::Control => {
                    // Control frames have varying structure
                    parse_control_addrs(data, &frame_control)
                }
                FrameType::Management | FrameType::Data => {
                    // Management and data frames have 3-4 addresses
                    parse_data_mgmt_addrs(data, &frame_control)
                }
                FrameType::Extension => {
                    (None, None, None, None, None, 10)
                }
            };

        // Parse body
        let body_data = &data[body_offset..];
        let body = match frame_control.frame_type {
            FrameType::Management => {
                ManagementFrame::parse(frame_control.subtype, body_data)
                    .map(FrameBody::Management)
                    .unwrap_or_else(|| FrameBody::Unknown(body_data.to_vec()))
            }
            FrameType::Control => {
                ControlFrame::parse(frame_control.subtype, body_data)
                    .map(FrameBody::Control)
                    .unwrap_or_else(|| FrameBody::Unknown(body_data.to_vec()))
            }
            FrameType::Data => {
                DataFrame::parse(body_data, frame_control.protected)
                    .map(FrameBody::Data)
                    .unwrap_or_else(|| FrameBody::Unknown(body_data.to_vec()))
            }
            FrameType::Extension => {
                FrameBody::Unknown(body_data.to_vec())
            }
        };

        Some(Self {
            frame_control,
            duration,
            addr1,
            addr2,
            addr3,
            seq_control,
            addr4,
            qos_control,
            body,
        })
    }

    /// Get the BSSID if available
    pub fn bssid(&self) -> Option<MacAddr> {
        match (self.frame_control.to_ds, self.frame_control.from_ds) {
            (false, false) => self.addr3,  // IBSS: addr3 is BSSID
            (false, true) => self.addr2,   // From AP: addr2 is BSSID
            (true, false) => Some(self.addr1),   // To AP: addr1 is BSSID
            (true, true) => None,          // WDS: no BSSID
        }
    }

    /// Get the source address
    pub fn source(&self) -> Option<MacAddr> {
        match (self.frame_control.to_ds, self.frame_control.from_ds) {
            (false, false) => self.addr2,
            (false, true) => self.addr3,
            (true, false) => self.addr2,
            (true, true) => self.addr4,
        }
    }

    /// Get the destination address
    pub fn destination(&self) -> Option<MacAddr> {
        match (self.frame_control.to_ds, self.frame_control.from_ds) {
            (false, false) => Some(self.addr1),
            (false, true) => Some(self.addr1),
            (true, false) => self.addr3,
            (true, true) => self.addr3,
        }
    }

    /// Check if this is a management frame
    pub fn is_management(&self) -> bool {
        self.frame_control.frame_type == FrameType::Management
    }

    /// Check if this is a control frame
    pub fn is_control(&self) -> bool {
        self.frame_control.frame_type == FrameType::Control
    }

    /// Check if this is a data frame
    pub fn is_data(&self) -> bool {
        self.frame_control.frame_type == FrameType::Data
    }

    /// Get sequence number
    pub fn sequence_number(&self) -> Option<u16> {
        self.seq_control.map(|sc| sc >> 4)
    }

    /// Get fragment number
    pub fn fragment_number(&self) -> Option<u8> {
        self.seq_control.map(|sc| (sc & 0x0f) as u8)
    }
}

fn parse_control_addrs(data: &[u8], fc: &FrameControl) -> (Option<MacAddr>, Option<MacAddr>, Option<u16>, Option<MacAddr>, Option<u16>, usize) {
    // Control frames don't have addr2/addr3 for some subtypes
    match fc.subtype {
        FrameSubtype::Cts | FrameSubtype::Ack => {
            // Only addr1 (receiver)
            (None, None, None, None, None, 10)
        }
        FrameSubtype::Rts | FrameSubtype::PsPoll | FrameSubtype::CfEnd | FrameSubtype::CfEndCfAck => {
            // addr1 and addr2
            if data.len() >= 16 {
                let addr2 = MacAddr::from_slice(&data[10..]);
                (addr2, None, None, None, None, 16)
            } else {
                (None, None, None, None, None, 10)
            }
        }
        FrameSubtype::BlockAck | FrameSubtype::BlockAckRequest => {
            // addr1, addr2, and BA control
            if data.len() >= 18 {
                let addr2 = MacAddr::from_slice(&data[10..]);
                (addr2, None, None, None, None, 18)
            } else {
                (None, None, None, None, None, 10)
            }
        }
        _ => (None, None, None, None, None, 10)
    }
}

fn parse_data_mgmt_addrs(data: &[u8], fc: &FrameControl) -> (Option<MacAddr>, Option<MacAddr>, Option<u16>, Option<MacAddr>, Option<u16>, usize) {
    if data.len() < 24 {
        return (None, None, None, None, None, 10);
    }

    let addr2 = MacAddr::from_slice(&data[10..]);
    let addr3 = MacAddr::from_slice(&data[16..]);
    let seq_control = Some(u16::from_le_bytes([data[22], data[23]]));

    let mut offset = 24;
    let mut addr4 = None;
    let mut qos = None;

    // Address 4 for WDS (to_ds && from_ds)
    if fc.to_ds && fc.from_ds && data.len() >= 30 {
        addr4 = MacAddr::from_slice(&data[24..]);
        offset = 30;
    }

    // QoS control for QoS data frames
    if fc.frame_type == FrameType::Data && matches!(fc.subtype,
        FrameSubtype::QosData |
        FrameSubtype::QosDataCfAck |
        FrameSubtype::QosDataCfPoll |
        FrameSubtype::QosDataCfAckCfPoll |
        FrameSubtype::QosNull |
        FrameSubtype::QosNullCfAck |
        FrameSubtype::QosNullCfPoll |
        FrameSubtype::QosNullCfAckCfPoll
    ) {
        if data.len() >= offset + 2 {
            qos = Some(u16::from_le_bytes([data[offset], data[offset + 1]]));
            offset += 2;
        }
    }

    (addr2, addr3, seq_control, addr4, qos, offset)
}
