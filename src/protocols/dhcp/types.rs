//! DHCP protocol types
pub const DHCP_KEYWORDS: &[&str] = &["dhcp.type", "dhcp.hostname", "dhcp.client_id", "dhcp.requested_ip"];
pub const DHCP_DISCOVER: u8 = 1; pub const DHCP_OFFER: u8 = 2; pub const DHCP_REQUEST: u8 = 3;
pub const DHCP_DECLINE: u8 = 4; pub const DHCP_ACK: u8 = 5; pub const DHCP_NAK: u8 = 6; pub const DHCP_RELEASE: u8 = 7;
pub const DHCP_MAGIC: [u8; 4] = [0x63, 0x82, 0x53, 0x63];
