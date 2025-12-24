//! IKE/IPsec protocol types
pub const IKE_KEYWORDS: &[&str] = &["ike.init_spi", "ike.resp_spi", "ike.version", "ike.exchange_type", "ike.flags", "ike.message_id", "ike.vendor_id", "ike.key_exchange", "ike.nonce"];

pub const IKE_EXCHANGE_TYPES: &[(u8, &str)] = &[
    // IKEv1
    (0, "None"), (1, "Base"), (2, "Identity Protection (Main Mode)"),
    (3, "Authentication Only"), (4, "Aggressive"), (5, "Informational"),
    (32, "Quick Mode"), (33, "New Group Mode"),
    // IKEv2
    (34, "IKE_SA_INIT"), (35, "IKE_AUTH"), (36, "CREATE_CHILD_SA"), (37, "INFORMATIONAL"),
];

pub const WEAK_TRANSFORMS: &[&str] = &["DES", "3DES", "MD5", "SHA1"];
