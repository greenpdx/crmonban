//! RFB/VNC protocol types
pub const RFB_KEYWORDS: &[&str] = &["rfb.version", "rfb.sectype", "rfb.secresult", "rfb.name"];

pub const RFB_SECURITY_TYPES: &[(u8, &str)] = &[
    (0, "Invalid"), (1, "None"), (2, "VNC Authentication"),
    (5, "RA2"), (6, "RA2ne"), (16, "Tight"), (17, "Ultra"),
    (18, "TLS"), (19, "VeNCrypt"), (30, "Apple Remote Desktop"),
];

pub const WEAK_SECURITY: &[u8] = &[1]; // None authentication
