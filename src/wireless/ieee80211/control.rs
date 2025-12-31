//! 802.11 Control Frame Types
//!
//! Control frames for medium access (ACK, RTS, CTS, Block ACK, etc.)

use super::frame::FrameSubtype;

/// Control frame variants
#[derive(Debug, Clone)]
pub enum ControlFrame {
    Ack,
    Cts,
    Rts,
    PsPoll { aid: u16 },
    BlockAckRequest(BlockAckReq),
    BlockAck(BlockAckResp),
    CfEnd,
    CfEndCfAck,
    Unknown(Vec<u8>),
}

impl ControlFrame {
    pub fn parse(subtype: FrameSubtype, data: &[u8]) -> Option<Self> {
        match subtype {
            FrameSubtype::Ack => Some(ControlFrame::Ack),
            FrameSubtype::Cts => Some(ControlFrame::Cts),
            FrameSubtype::Rts => Some(ControlFrame::Rts),
            FrameSubtype::CfEnd => Some(ControlFrame::CfEnd),
            FrameSubtype::CfEndCfAck => Some(ControlFrame::CfEndCfAck),
            FrameSubtype::PsPoll => {
                if data.len() >= 2 {
                    Some(ControlFrame::PsPoll {
                        aid: u16::from_le_bytes([data[0], data[1]]) & 0x3fff,
                    })
                } else {
                    Some(ControlFrame::PsPoll { aid: 0 })
                }
            }
            FrameSubtype::BlockAckRequest => {
                BlockAckReq::parse(data).map(ControlFrame::BlockAckRequest)
            }
            FrameSubtype::BlockAck => {
                BlockAckResp::parse(data).map(ControlFrame::BlockAck)
            }
            _ => Some(ControlFrame::Unknown(data.to_vec())),
        }
    }
}

/// Block ACK Request
#[derive(Debug, Clone)]
pub struct BlockAckReq {
    /// BAR control field
    pub control: u16,
    /// Starting sequence control
    pub starting_seq: u16,
    /// Is compressed bitmap
    pub compressed: bool,
    /// TID
    pub tid: u8,
}

impl BlockAckReq {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }

        let control = u16::from_le_bytes([data[0], data[1]]);
        let starting_seq = u16::from_le_bytes([data[2], data[3]]);

        Some(BlockAckReq {
            control,
            starting_seq,
            compressed: control & 0x0004 != 0,
            tid: ((control >> 12) & 0x0f) as u8,
        })
    }
}

/// Block ACK Response
#[derive(Debug, Clone)]
pub struct BlockAckResp {
    /// BA control field
    pub control: u16,
    /// Starting sequence control
    pub starting_seq: u16,
    /// Block ACK bitmap
    pub bitmap: Vec<u8>,
    /// TID
    pub tid: u8,
}

impl BlockAckResp {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }

        let control = u16::from_le_bytes([data[0], data[1]]);
        let starting_seq = u16::from_le_bytes([data[2], data[3]]);

        let compressed = control & 0x0004 != 0;
        let bitmap_len = if compressed { 8 } else { 128 };

        let bitmap = if data.len() >= 4 + bitmap_len {
            data[4..4 + bitmap_len].to_vec()
        } else {
            Vec::new()
        };

        Some(BlockAckResp {
            control,
            starting_seq,
            bitmap,
            tid: ((control >> 12) & 0x0f) as u8,
        })
    }
}
