//! NFS per-flow state
use std::any::Any;
use crate::protocols::traits::ProtocolStateData;

#[derive(Debug, Default)]
pub struct NfsState { pub version: u32, pub procedures: Vec<u32>, pub files_accessed: Vec<String>, pub mounts: Vec<String> }
impl NfsState { pub fn new() -> Self { Self::default() } }
impl ProtocolStateData for NfsState { fn as_any(&self) -> &dyn Any { self } fn as_any_mut(&mut self) -> &mut dyn Any { self } }
