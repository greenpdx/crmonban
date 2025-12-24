//! Kerberos protocol types
pub const KRB_KEYWORDS: &[&str] = &["krb5.cname", "krb5.sname", "krb5.msg_type", "krb5.weak_encryption", "krb5.encryption_type"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KrbMsgType { AsReq = 10, AsRep = 11, TgsReq = 12, TgsRep = 13, ApReq = 14, ApRep = 15, KrbError = 30 }
impl TryFrom<u8> for KrbMsgType { type Error = (); fn try_from(v: u8) -> Result<Self, ()> { match v { 10 => Ok(Self::AsReq), 11 => Ok(Self::AsRep), 12 => Ok(Self::TgsReq), 13 => Ok(Self::TgsRep), 14 => Ok(Self::ApReq), 15 => Ok(Self::ApRep), 30 => Ok(Self::KrbError), _ => Err(()) } } }

pub const WEAK_ENCRYPTION_TYPES: &[i32] = &[1, 3, 23, 24]; // DES, RC4
