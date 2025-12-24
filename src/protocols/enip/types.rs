//! EtherNet/IP protocol types
pub const ENIP_KEYWORDS: &[&str] = &["enip.command", "enip.status", "enip.session", "enip.length", "cip.service", "cip.path", "cip.data"];

pub const ENIP_COMMANDS: &[(u16, &str)] = &[
    (0x0001, "NOP"), (0x0004, "ListServices"), (0x0063, "ListIdentity"),
    (0x0064, "ListInterfaces"), (0x0065, "RegisterSession"), (0x0066, "UnregisterSession"),
    (0x006F, "SendRRData"), (0x0070, "SendUnitData"),
];

pub const DANGEROUS_CIP_SERVICES: &[u8] = &[0x4B, 0x4C, 0x4D, 0x52]; // Reset, start, stop, get attribute
