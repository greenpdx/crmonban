//! DCE/RPC protocol types

pub const DCERPC_KEYWORDS: &[&str] = &[
    "dcerpc.iface", "dcerpc.opnum", "dcerpc.stub_data",
    "dce_iface", "dce_opnum", "dce_stub_data",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DceRpcPacketType {
    Request = 0, Ping = 1, Response = 2, Fault = 3, Working = 4,
    NoCall = 5, Reject = 6, Ack = 7, ClCancel = 8, Fack = 9,
    CancelAck = 10, Bind = 11, BindAck = 12, BindNak = 13,
    AlterContext = 14, AlterContextResp = 15, Shutdown = 17,
    CoCancel = 18, Orphaned = 19,
}

impl TryFrom<u8> for DceRpcPacketType {
    type Error = ();
    fn try_from(v: u8) -> Result<Self, ()> {
        match v {
            0 => Ok(Self::Request), 1 => Ok(Self::Ping), 2 => Ok(Self::Response),
            3 => Ok(Self::Fault), 11 => Ok(Self::Bind), 12 => Ok(Self::BindAck),
            13 => Ok(Self::BindNak), 14 => Ok(Self::AlterContext),
            15 => Ok(Self::AlterContextResp), _ => Err(()),
        }
    }
}

pub mod interfaces {
    pub const SRVSVC: &str = "4b324fc8-1670-01d3-1278-5a47bf6ee188";
    pub const SVCCTL: &str = "367abb81-9844-35f1-ad32-98f038001003";
    pub const SAMR: &str = "12345778-1234-abcd-ef00-0123456789ac";
    pub const LSARPC: &str = "12345778-1234-abcd-ef00-0123456789ab";
    pub const DRSUAPI: &str = "e3514235-4b06-11d1-ab04-00c04fc2dcd2";
    pub const SPOOLSS: &str = "12345678-1234-abcd-ef00-0123456789ab";
    pub const EPMAPPER: &str = "e1af8308-5d1f-11c9-91a4-08002b14a0fa";
}

pub const SUSPICIOUS_INTERFACES: &[(&str, &str)] = &[
    (interfaces::DRSUAPI, "DCSync"), (interfaces::SVCCTL, "PsExec"),
    (interfaces::SPOOLSS, "PrintNightmare"),
];

#[derive(Debug, Clone)]
pub struct Uuid { pub data: [u8; 16] }

impl Uuid {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 16 { return None; }
        let mut data = [0u8; 16];
        data.copy_from_slice(&bytes[..16]);
        Some(Self { data })
    }
    pub fn to_string(&self) -> String {
        format!("{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.data[3], self.data[2], self.data[1], self.data[0],
            self.data[5], self.data[4], self.data[7], self.data[6],
            self.data[8], self.data[9], self.data[10], self.data[11],
            self.data[12], self.data[13], self.data[14], self.data[15])
    }
}
