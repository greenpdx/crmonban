//! Protocol registry for dynamic protocol detection and dispatch
//!
//! Manages registration of protocol parsers and provides port-based
//! and content-based protocol detection.

use std::collections::HashMap;

use crate::core::Direction;
use crate::signatures::ast::Protocol;
use super::traits::ProtocolParser;
use super::alerts::ProtocolAlert;
use crate::types::DetectionType;

/// Protocol registration entry
pub struct ProtocolRegistration {
    /// Protocol identifier (e.g., "smb", "ftp")
    pub name: &'static str,

    /// Protocol enum for rule filtering
    pub protocol: Protocol,

    /// Default TCP ports
    pub tcp_ports: &'static [u16],

    /// Default UDP ports
    pub udp_ports: &'static [u16],

    /// Factory function to create new parser instance
    pub create_parser: fn() -> Box<dyn ProtocolParser>,

    /// Detection priority (higher = checked first during probing)
    pub priority: u8,

    /// Suricata keywords this protocol provides
    pub keywords: &'static [&'static str],
}

impl ProtocolRegistration {
    /// Create a new parser instance
    pub fn new_parser(&self) -> Box<dyn ProtocolParser> {
        (self.create_parser)()
    }
}

/// Global protocol registry
///
/// Manages all registered protocol parsers and provides
/// lookup by port and protocol detection.
pub struct ProtocolRegistry {
    /// Registered protocols
    protocols: Vec<ProtocolRegistration>,

    /// TCP port → protocol indices (sorted by priority)
    tcp_ports: HashMap<u16, Vec<usize>>,

    /// UDP port → protocol indices (sorted by priority)
    udp_ports: HashMap<u16, Vec<usize>>,

    /// Protocol enum → index
    by_protocol: HashMap<Protocol, usize>,

    /// Protocol name → index
    by_name: HashMap<&'static str, usize>,
}

impl ProtocolRegistry {
    /// Create new empty registry
    pub fn new() -> Self {
        Self {
            protocols: Vec::new(),
            tcp_ports: HashMap::new(),
            udp_ports: HashMap::new(),
            by_protocol: HashMap::new(),
            by_name: HashMap::new(),
        }
    }

    /// Register a protocol
    pub fn register(&mut self, reg: ProtocolRegistration) {
        let idx = self.protocols.len();

        // Index by protocol enum
        self.by_protocol.insert(reg.protocol, idx);

        // Index by name
        self.by_name.insert(reg.name, idx);

        // Index by TCP ports
        for &port in reg.tcp_ports {
            self.tcp_ports
                .entry(port)
                .or_insert_with(Vec::new)
                .push(idx);
        }

        // Index by UDP ports
        for &port in reg.udp_ports {
            self.udp_ports
                .entry(port)
                .or_insert_with(Vec::new)
                .push(idx);
        }

        self.protocols.push(reg);

        // Re-sort port mappings by priority (higher first)
        for indices in self.tcp_ports.values_mut() {
            indices.sort_by(|&a, &b| {
                self.protocols[b].priority.cmp(&self.protocols[a].priority)
            });
        }
        for indices in self.udp_ports.values_mut() {
            indices.sort_by(|&a, &b| {
                self.protocols[b].priority.cmp(&self.protocols[a].priority)
            });
        }
    }

    /// Get protocols registered for a TCP port
    pub fn for_tcp_port(&self, port: u16) -> impl Iterator<Item = &ProtocolRegistration> {
        self.tcp_ports
            .get(&port)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
            .iter()
            .map(|&idx| &self.protocols[idx])
    }

    /// Get protocols registered for a UDP port
    pub fn for_udp_port(&self, port: u16) -> impl Iterator<Item = &ProtocolRegistration> {
        self.udp_ports
            .get(&port)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
            .iter()
            .map(|&idx| &self.protocols[idx])
    }

    /// Get registration by protocol enum
    pub fn get(&self, protocol: Protocol) -> Option<&ProtocolRegistration> {
        self.by_protocol.get(&protocol).map(|&idx| &self.protocols[idx])
    }

    /// Get registration by name
    pub fn get_by_name(&self, name: &str) -> Option<&ProtocolRegistration> {
        self.by_name.get(name).map(|&idx| &self.protocols[idx])
    }

    /// Probe all registered protocols against payload
    ///
    /// Returns the best matching protocol registration based on probe confidence.
    pub fn detect(
        &self,
        payload: &[u8],
        direction: Direction,
    ) -> Option<&ProtocolRegistration> {
        let mut best: Option<(u8, usize)> = None;

        for (idx, reg) in self.protocols.iter().enumerate() {
            let parser = reg.new_parser();
            let confidence = parser.probe(payload, direction);

            if confidence > 0 {
                match best {
                    None => best = Some((confidence, idx)),
                    Some((best_conf, _)) if confidence > best_conf => {
                        best = Some((confidence, idx));
                    }
                    _ => {}
                }
            }
        }

        best.map(|(_, idx)| &self.protocols[idx])
    }

    /// Probe protocols for a specific port
    ///
    /// More efficient than detect() when port is known.
    pub fn detect_for_port(
        &self,
        port: u16,
        is_tcp: bool,
        payload: &[u8],
        direction: Direction,
    ) -> Option<&ProtocolRegistration> {
        let indices = if is_tcp {
            self.tcp_ports.get(&port)
        } else {
            self.udp_ports.get(&port)
        };

        let Some(indices) = indices else {
            // No protocols registered for this port, try all
            return self.detect(payload, direction);
        };

        // Try protocols registered for this port first (already sorted by priority)
        for &idx in indices {
            let reg = &self.protocols[idx];
            let parser = reg.new_parser();
            let confidence = parser.probe(payload, direction);

            if confidence >= 50 {
                return Some(reg);
            }
        }

        // If no match on registered ports, try detecting across all protocols
        self.detect(payload, direction)
    }

    /// Get all registered protocols
    pub fn all(&self) -> impl Iterator<Item = &ProtocolRegistration> {
        self.protocols.iter()
    }

    /// Number of registered protocols
    pub fn len(&self) -> usize {
        self.protocols.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.protocols.is_empty()
    }

    /// Get all keywords across all protocols
    pub fn all_keywords(&self) -> Vec<&'static str> {
        self.protocols
            .iter()
            .flat_map(|reg| reg.keywords.iter().copied())
            .collect()
    }
}

impl Default for ProtocolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Check for port mismatch and generate alert if protocol
/// detected on non-standard port
pub fn check_port_mismatch(
    detected_protocol: Protocol,
    actual_port: u16,
    is_tcp: bool,
    registry: &ProtocolRegistry,
) -> Option<ProtocolAlert> {
    let reg = registry.get(detected_protocol)?;

    let expected_ports = if is_tcp {
        reg.tcp_ports
    } else {
        reg.udp_ports
    };

    if !expected_ports.contains(&actual_port) {
        Some(ProtocolAlert {
            sid: 0, // Protocol-generated, no signature
            msg: format!(
                "{} detected on non-standard port {}",
                reg.name.to_uppercase(),
                actual_port
            ),
            detection_type: DetectionType::ProtocolAnomaly,
            severity: crate::core::Severity::Medium,
            classtype: Some("protocol-anomaly".to_string()),
            metadata: std::collections::HashMap::from([
                ("protocol".to_string(), reg.name.to_string()),
                ("expected_ports".to_string(), format!("{:?}", expected_ports)),
                ("actual_port".to_string(), actual_port.to_string()),
            ]),
            match_info: None,
        })
    } else {
        None
    }
}

/// Macro for easy protocol registration
#[macro_export]
macro_rules! register_protocol {
    ($registry:expr, $module:ident) => {
        $registry.register($module::registration())
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_registration(name: &'static str, protocol: Protocol, ports: &'static [u16]) -> ProtocolRegistration {
        ProtocolRegistration {
            name,
            protocol,
            tcp_ports: ports,
            udp_ports: &[],
            create_parser: || unimplemented!("mock parser"),
            priority: 50,
            keywords: &[],
        }
    }

    #[test]
    fn test_registry_register() {
        let mut registry = ProtocolRegistry::new();
        registry.register(mock_registration("http", Protocol::Http, &[80, 8080]));
        registry.register(mock_registration("ssh", Protocol::Ssh, &[22]));

        assert_eq!(registry.len(), 2);
        assert!(registry.get(Protocol::Http).is_some());
        assert!(registry.get(Protocol::Ssh).is_some());
        assert!(registry.get(Protocol::Smb).is_none());
    }

    #[test]
    fn test_registry_port_lookup() {
        let mut registry = ProtocolRegistry::new();
        registry.register(mock_registration("http", Protocol::Http, &[80, 8080]));
        registry.register(mock_registration("ssh", Protocol::Ssh, &[22]));

        let http_protocols: Vec<_> = registry.for_tcp_port(80).collect();
        assert_eq!(http_protocols.len(), 1);
        assert_eq!(http_protocols[0].name, "http");

        let empty: Vec<_> = registry.for_tcp_port(12345).collect();
        assert!(empty.is_empty());
    }

    #[test]
    fn test_port_mismatch() {
        let mut registry = ProtocolRegistry::new();
        registry.register(mock_registration("ssh", Protocol::Ssh, &[22]));

        // SSH on port 22 - no alert
        let alert = check_port_mismatch(Protocol::Ssh, 22, true, &registry);
        assert!(alert.is_none());

        // SSH on port 2222 - alert
        let alert = check_port_mismatch(Protocol::Ssh, 2222, true, &registry);
        assert!(alert.is_some());
        assert!(alert.unwrap().msg.contains("non-standard port"));
    }
}
