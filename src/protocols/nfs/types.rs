//! NFS protocol types
pub const NFS_KEYWORDS: &[&str] = &["nfs.procedure", "nfs.filename", "nfs.version"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfsProcedure { Null = 0, GetAttr = 1, SetAttr = 2, Lookup = 3, Access = 4, ReadLink = 5, Read = 6, Write = 7, Create = 8, MkDir = 9, SymLink = 10, MkNod = 11, Remove = 12, RmDir = 13, Rename = 14, Link = 15, ReadDir = 16, ReadDirPlus = 17, FsStat = 18, FsInfo = 19, PathConf = 20, Commit = 21 }
impl TryFrom<u32> for NfsProcedure {
    type Error = ();
    fn try_from(v: u32) -> Result<Self, ()> { match v { 0 => Ok(Self::Null), 1 => Ok(Self::GetAttr), 3 => Ok(Self::Lookup), 6 => Ok(Self::Read), 7 => Ok(Self::Write), 8 => Ok(Self::Create), 12 => Ok(Self::Remove), _ => Err(()) } }
}
