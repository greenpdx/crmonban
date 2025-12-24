//! FTP per-flow state
use std::any::Any;
use crate::protocols::traits::ProtocolStateData;

#[derive(Debug, Default)]
pub struct FtpState {
    pub username: Option<String>,
    pub authenticated: bool,
    pub auth_failures: u32,
    pub current_dir: Option<String>,
    pub commands: Vec<String>,
    pub data_port: Option<u16>,
    pub passive_mode: bool,
    pub files_transferred: Vec<String>,
    pub bounce_attack: bool,
}

impl FtpState {
    pub fn new() -> Self { Self::default() }
}

impl ProtocolStateData for FtpState {
    fn as_any(&self) -> &dyn Any { self }
    fn as_any_mut(&mut self) -> &mut dyn Any { self }
}
