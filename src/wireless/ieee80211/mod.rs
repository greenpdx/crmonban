//! 802.11 Frame Parsing
//!
//! This module provides parsing for IEEE 802.11 wireless frames.

mod frame;
mod management;
mod control;
mod data;

pub use frame::*;
pub use management::*;
pub use control::*;
pub use data::*;

/// Parse an 802.11 frame from bytes
pub fn parse_ieee80211(data: &[u8]) -> Option<Ieee80211Frame> {
    Ieee80211Frame::parse(data)
}
