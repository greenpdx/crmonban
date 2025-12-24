//! NTP protocol types
pub const NTP_KEYWORDS: &[&str] = &["ntp.mode", "ntp.version", "ntp.stratum", "ntp.request", "ntp.response"];

pub const NTP_MODES: &[(u8, &str)] = &[
    (0, "Reserved"), (1, "Symmetric Active"), (2, "Symmetric Passive"),
    (3, "Client"), (4, "Server"), (5, "Broadcast"), (6, "Control"), (7, "Private"),
];

pub const MONLIST_CMD: u8 = 42; // MON_GETLIST_1
