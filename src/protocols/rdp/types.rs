//! RDP protocol types
pub const RDP_KEYWORDS: &[&str] = &["rdp.cookie", "rdp.client_name", "rdp.keyboard"];
pub const TPKT_VERSION: u8 = 3;
pub const X224_CONNECTION_REQUEST: u8 = 0xe0;
pub const X224_CONNECTION_CONFIRM: u8 = 0xd0;
