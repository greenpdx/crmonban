//! IP filtering module
//!
//! Provides IP address filtering with support for:
//! - Blocked IPs (deny list)
//! - Watch list (monitoring/logging)
//! - Clean IPs (allow list)
//! - GeoIP-based filtering

pub mod geoip;
pub mod ipfilter;

pub use geoip::GeoIpFilter;
pub use ipfilter::{IpFilter, IpStatus};
