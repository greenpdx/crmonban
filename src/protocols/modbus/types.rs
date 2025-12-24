//! Modbus protocol types
pub const MODBUS_KEYWORDS: &[&str] = &["modbus.function", "modbus.unit_id", "modbus.access_type", "modbus.address", "modbus.quantity", "modbus.data", "modbus.exception"];

pub const MODBUS_FUNCTIONS: &[(u8, &str)] = &[
    (1, "Read Coils"), (2, "Read Discrete Inputs"), (3, "Read Holding Registers"),
    (4, "Read Input Registers"), (5, "Write Single Coil"), (6, "Write Single Register"),
    (15, "Write Multiple Coils"), (16, "Write Multiple Registers"), (22, "Mask Write Register"),
    (23, "Read/Write Multiple Registers"), (43, "Encapsulated Interface Transport"),
];

pub const DANGEROUS_FUNCTIONS: &[u8] = &[5, 6, 15, 16, 22, 23]; // Write functions
pub const DIAGNOSTIC_FUNCTIONS: &[u8] = &[8, 17, 43]; // Device identification/diagnostics
