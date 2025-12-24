//! DNP3 protocol types
pub const DNP3_KEYWORDS: &[&str] = &["dnp3.header", "dnp3.data", "dnp3.func", "dnp3.ind", "dnp3.obj", "dnp3.iin"];

pub const DNP3_FUNCTIONS: &[(u8, &str)] = &[
    (0, "CONFIRM"), (1, "READ"), (2, "WRITE"), (3, "SELECT"), (4, "OPERATE"),
    (5, "DIRECT_OPERATE"), (6, "DIRECT_OPERATE_NR"), (7, "IMMED_FREEZE"),
    (8, "IMMED_FREEZE_NR"), (9, "FREEZE_CLEAR"), (10, "FREEZE_CLEAR_NR"),
    (13, "COLD_RESTART"), (14, "WARM_RESTART"), (15, "INITIALIZE_DATA"),
    (16, "INITIALIZE_APPL"), (17, "START_APPL"), (18, "STOP_APPL"),
    (20, "ENABLE_UNSOLICITED"), (21, "DISABLE_UNSOLICITED"),
    (129, "RESPONSE"), (130, "UNSOLICITED_RESPONSE"),
];

pub const DANGEROUS_DNP3_FUNCTIONS: &[u8] = &[2, 3, 4, 5, 6, 13, 14, 15, 16, 17, 18]; // Write/control/restart
pub const DNP3_START_BYTES: (u8, u8) = (0x05, 0x64);
