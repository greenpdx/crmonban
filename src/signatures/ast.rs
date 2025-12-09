//! Abstract Syntax Tree for Suricata/Snort rules
//!
//! Defines the data structures representing parsed detection rules.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Rule action - what to do when rule matches
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Generate an alert
    Alert,
    /// Drop the packet (IPS mode)
    Drop,
    /// Reject with RST/ICMP unreachable
    Reject,
    /// Allow through without alerting
    Pass,
    /// Log only, no alert
    Log,
}

impl Default for Action {
    fn default() -> Self {
        Action::Alert
    }
}

impl std::str::FromStr for Action {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "alert" => Ok(Action::Alert),
            "drop" => Ok(Action::Drop),
            "reject" => Ok(Action::Reject),
            "pass" => Ok(Action::Pass),
            "log" => Ok(Action::Log),
            _ => Err(format!("Unknown action: {}", s)),
        }
    }
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Action::Alert => write!(f, "alert"),
            Action::Drop => write!(f, "drop"),
            Action::Reject => write!(f, "reject"),
            Action::Pass => write!(f, "pass"),
            Action::Log => write!(f, "log"),
        }
    }
}

/// Protocol specification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Ip,
    // Application layer protocols
    Http,
    Dns,
    Tls,
    Ssh,
    Ftp,
    Smtp,
    Smb,
    Dcerpc,
    Dhcp,
    Ntp,
    // Generic
    Any,
}

impl Default for Protocol {
    fn default() -> Self {
        Protocol::Any
    }
}

impl std::str::FromStr for Protocol {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "tcp" => Ok(Protocol::Tcp),
            "udp" => Ok(Protocol::Udp),
            "icmp" => Ok(Protocol::Icmp),
            "ip" => Ok(Protocol::Ip),
            "http" => Ok(Protocol::Http),
            "dns" => Ok(Protocol::Dns),
            "tls" | "ssl" => Ok(Protocol::Tls),
            "ssh" => Ok(Protocol::Ssh),
            "ftp" => Ok(Protocol::Ftp),
            "smtp" => Ok(Protocol::Smtp),
            "smb" => Ok(Protocol::Smb),
            "dcerpc" => Ok(Protocol::Dcerpc),
            "dhcp" => Ok(Protocol::Dhcp),
            "ntp" => Ok(Protocol::Ntp),
            "any" => Ok(Protocol::Any),
            _ => Err(format!("Unknown protocol: {}", s)),
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
            Protocol::Icmp => write!(f, "icmp"),
            Protocol::Ip => write!(f, "ip"),
            Protocol::Http => write!(f, "http"),
            Protocol::Dns => write!(f, "dns"),
            Protocol::Tls => write!(f, "tls"),
            Protocol::Ssh => write!(f, "ssh"),
            Protocol::Ftp => write!(f, "ftp"),
            Protocol::Smtp => write!(f, "smtp"),
            Protocol::Smb => write!(f, "smb"),
            Protocol::Dcerpc => write!(f, "dcerpc"),
            Protocol::Dhcp => write!(f, "dhcp"),
            Protocol::Ntp => write!(f, "ntp"),
            Protocol::Any => write!(f, "any"),
        }
    }
}

/// IP address specification
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IpSpec {
    /// Match any IP
    Any,
    /// Variable reference ($HOME_NET, $EXTERNAL_NET, etc.)
    Var(String),
    /// Single IP address
    Single(IpAddr),
    /// CIDR notation (192.168.1.0/24)
    Cidr(IpAddr, u8),
    /// IP range (192.168.1.1-192.168.1.100)
    Range(IpAddr, IpAddr),
    /// List of IP specs [192.168.1.0/24, 10.0.0.0/8]
    List(Vec<IpSpec>),
    /// Negated IP spec (!192.168.1.1)
    Negated(Box<IpSpec>),
}

impl Default for IpSpec {
    fn default() -> Self {
        IpSpec::Any
    }
}

impl std::fmt::Display for IpSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpSpec::Any => write!(f, "any"),
            IpSpec::Var(name) => write!(f, "${}", name),
            IpSpec::Single(ip) => write!(f, "{}", ip),
            IpSpec::Cidr(ip, prefix) => write!(f, "{}/{}", ip, prefix),
            IpSpec::Range(start, end) => write!(f, "{}-{}", start, end),
            IpSpec::List(list) => {
                write!(f, "[")?;
                for (i, spec) in list.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "{}", spec)?;
                }
                write!(f, "]")
            }
            IpSpec::Negated(inner) => write!(f, "!{}", inner),
        }
    }
}

/// Port specification
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PortSpec {
    /// Match any port
    Any,
    /// Variable reference ($HTTP_PORTS, etc.)
    Var(String),
    /// Single port
    Single(u16),
    /// Port range (1024:65535)
    Range(u16, u16),
    /// List of port specs [80, 443, 8080]
    List(Vec<PortSpec>),
    /// Negated port spec (!22)
    Negated(Box<PortSpec>),
}

impl Default for PortSpec {
    fn default() -> Self {
        PortSpec::Any
    }
}

impl std::fmt::Display for PortSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortSpec::Any => write!(f, "any"),
            PortSpec::Var(name) => write!(f, "${}", name),
            PortSpec::Single(port) => write!(f, "{}", port),
            PortSpec::Range(start, end) => write!(f, "{}:{}", start, end),
            PortSpec::List(list) => {
                write!(f, "[")?;
                for (i, spec) in list.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "{}", spec)?;
                }
                write!(f, "]")
            }
            PortSpec::Negated(inner) => write!(f, "!{}", inner),
        }
    }
}

/// Traffic direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    /// Source to destination (->)
    ToServer,
    /// Destination to source (<-)
    ToClient,
    /// Bidirectional (<>)
    Both,
}

impl Default for Direction {
    fn default() -> Self {
        Direction::ToServer
    }
}

impl std::fmt::Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Direction::ToServer => write!(f, "->"),
            Direction::ToClient => write!(f, "<-"),
            Direction::Both => write!(f, "<>"),
        }
    }
}

/// Content match options
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContentMatch {
    /// Pattern bytes to match
    pub pattern: Vec<u8>,
    /// Negated match (!content)
    pub negated: bool,
    /// Case insensitive matching
    pub nocase: bool,
    /// Absolute offset from start of payload
    pub offset: Option<u32>,
    /// Maximum depth to search
    pub depth: Option<u32>,
    /// Relative distance from last match
    pub distance: Option<i32>,
    /// Must match within N bytes of last match
    pub within: Option<u32>,
    /// Use for fast pre-filtering
    pub fast_pattern: bool,
    /// Match on raw bytes (not normalized)
    pub rawbytes: bool,
}

impl Default for ContentMatch {
    fn default() -> Self {
        Self {
            pattern: Vec::new(),
            negated: false,
            nocase: false,
            offset: None,
            depth: None,
            distance: None,
            within: None,
            fast_pattern: false,
            rawbytes: false,
        }
    }
}

/// PCRE regex match options
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PcreMatch {
    /// Regex pattern
    pub pattern: String,
    /// Regex flags (i, s, m, x, etc.)
    pub flags: String,
    /// Negated match
    pub negated: bool,
    /// Relative to last match (R flag)
    pub relative: bool,
}

impl Default for PcreMatch {
    fn default() -> Self {
        Self {
            pattern: String::new(),
            flags: String::new(),
            negated: false,
            relative: false,
        }
    }
}

/// Byte test operation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ByteTest {
    /// Number of bytes to convert
    pub num_bytes: u8,
    /// Comparison operator
    pub operator: ByteTestOp,
    /// Value to compare against
    pub value: u64,
    /// Offset from start or last match
    pub offset: i32,
    /// Relative to last match
    pub relative: bool,
    /// Endianness
    pub endian: Endian,
    /// Treat as string
    pub string: bool,
    /// Base for string conversion
    pub base: Base,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ByteTestOp {
    Equal,
    NotEqual,
    LessThan,
    GreaterThan,
    LessOrEqual,
    GreaterOrEqual,
    BitwiseAnd,
    BitwiseOr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Endian {
    #[default]
    Big,
    Little,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Base {
    #[default]
    Dec,
    Hex,
    Oct,
}

/// Flow state flags
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FlowFlags {
    pub to_server: bool,
    pub to_client: bool,
    pub from_server: bool,
    pub from_client: bool,
    pub established: bool,
    pub not_established: bool,
    pub stateless: bool,
    pub only_stream: bool,
    pub no_stream: bool,
    pub only_frag: bool,
    pub no_frag: bool,
}

/// Flowbits operations
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FlowbitsOp {
    Set(String),
    Unset(String),
    Toggle(String),
    IsSet(String),
    IsNotSet(String),
    NoAlert,
}

/// Threshold/detection filter
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThresholdSpec {
    pub threshold_type: ThresholdType,
    pub track: TrackBy,
    pub count: u32,
    pub seconds: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThresholdType {
    Limit,
    Threshold,
    Both,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrackBy {
    BySrc,
    ByDst,
    ByRule,
    ByBoth,
}

/// TCP flags for matching
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TcpFlags {
    pub fin: Option<bool>,
    pub syn: Option<bool>,
    pub rst: Option<bool>,
    pub psh: Option<bool>,
    pub ack: Option<bool>,
    pub urg: Option<bool>,
    pub ece: Option<bool>,
    pub cwr: Option<bool>,
    pub match_all: bool,  // + modifier
    pub match_any: bool,  // * modifier
    pub ignore_reserved: bool,
}

/// Size/length comparison
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SizeMatch {
    pub operator: CompareOp,
    pub value: u32,
    pub value2: Option<u32>, // For range (e.g., dsize:100<>200)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompareOp {
    Equal,
    NotEqual,
    LessThan,
    GreaterThan,
    LessOrEqual,
    GreaterOrEqual,
    Range,
}

/// Rule reference
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Reference {
    pub ref_type: String,
    pub ref_id: String,
}

/// Rule metadata key-value pair
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Metadata {
    pub key: String,
    pub value: String,
}

/// All possible rule options
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RuleOption {
    // ═══════════════════════════════════════════════════════════════════════════
    // Metadata options
    // ═══════════════════════════════════════════════════════════════════════════
    /// Alert message
    Msg(String),
    /// Signature ID
    Sid(u32),
    /// Revision number
    Rev(u32),
    /// Group ID
    Gid(u32),
    /// Classification type
    Classtype(String),
    /// Priority (1-4, 1 = highest)
    Priority(u8),
    /// External reference
    Reference(Reference),
    /// Metadata key-value pairs
    Metadata(Vec<Metadata>),
    /// Target of attack
    Target(String),

    // ═══════════════════════════════════════════════════════════════════════════
    // Payload detection
    // ═══════════════════════════════════════════════════════════════════════════
    /// Content match
    Content(ContentMatch),
    /// PCRE regex
    Pcre(PcreMatch),
    /// Byte test
    ByteTest(ByteTest),
    /// Byte jump
    ByteJump {
        num_bytes: u8,
        offset: i32,
        relative: bool,
        multiplier: Option<u32>,
        post_offset: Option<i32>,
        endian: Endian,
        string: bool,
        base: Base,
        from_beginning: bool,
        from_end: bool,
        align: bool,
    },
    /// Byte extract
    ByteExtract {
        num_bytes: u8,
        offset: i32,
        name: String,
        relative: bool,
        multiplier: Option<u32>,
        endian: Endian,
        string: bool,
        base: Base,
        align: bool,
    },
    /// Match on Base64 decoded data
    Base64Decode {
        bytes: Option<u32>,
        offset: Option<u32>,
        relative: bool,
    },
    /// Match within Base64 decoded buffer
    Base64Data,
    /// Payload size
    Dsize(SizeMatch),
    /// isDataAt
    IsDataAt {
        position: u32,
        relative: bool,
        negated: bool,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // Flow options
    // ═══════════════════════════════════════════════════════════════════════════
    /// Flow direction and state
    Flow(FlowFlags),
    /// Flowbits operations
    Flowbits(FlowbitsOp),
    /// Stream size
    StreamSize {
        direction: String,
        operator: CompareOp,
        value: u32,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // Thresholds and rate limiting
    // ═══════════════════════════════════════════════════════════════════════════
    /// Threshold
    Threshold(ThresholdSpec),
    /// Detection filter
    DetectionFilter(ThresholdSpec),

    // ═══════════════════════════════════════════════════════════════════════════
    // HTTP options
    // ═══════════════════════════════════════════════════════════════════════════
    /// HTTP URI buffer
    HttpUri,
    /// HTTP raw URI
    HttpRawUri,
    /// HTTP method
    HttpMethod,
    /// HTTP request line
    HttpRequestLine,
    /// HTTP header
    HttpHeader,
    /// HTTP raw header
    HttpRawHeader,
    /// HTTP cookie
    HttpCookie,
    /// HTTP User-Agent
    HttpUserAgent,
    /// HTTP Host
    HttpHost,
    /// HTTP raw host
    HttpRawHost,
    /// HTTP Accept
    HttpAccept,
    /// HTTP Accept-Encoding
    HttpAcceptEnc,
    /// HTTP Accept-Language
    HttpAcceptLang,
    /// HTTP Connection
    HttpConnection,
    /// HTTP Content-Type
    HttpContentType,
    /// HTTP Content-Length
    HttpContentLen,
    /// HTTP Referer
    HttpReferer,
    /// HTTP request body
    HttpClientBody,
    /// HTTP response body
    HttpServerBody,
    /// HTTP status code
    HttpStatCode,
    /// HTTP status message
    HttpStatMsg,
    /// HTTP response line
    HttpResponseLine,
    /// HTTP protocol/version
    HttpProtocol,
    /// HTTP request start
    HttpStart,
    /// HTTP header names
    HttpHeaderNames,

    // ═══════════════════════════════════════════════════════════════════════════
    // DNS options
    // ═══════════════════════════════════════════════════════════════════════════
    /// DNS query
    DnsQuery,
    /// DNS opcode
    DnsOpcode(u8),
    /// DNS answer
    DnsAnswer,

    // ═══════════════════════════════════════════════════════════════════════════
    // TLS options
    // ═══════════════════════════════════════════════════════════════════════════
    /// TLS SNI
    TlsSni,
    /// TLS cert subject
    TlsCertSubject,
    /// TLS cert issuer
    TlsCertIssuer,
    /// TLS cert serial
    TlsCertSerial,
    /// TLS cert fingerprint
    TlsCertFingerprint,
    /// TLS version
    TlsVersion(String),
    /// JA3 hash
    Ja3Hash,
    /// JA3 string
    Ja3String,
    /// JA3S hash
    Ja3sHash,
    /// JA3S string
    Ja3sString,

    // ═══════════════════════════════════════════════════════════════════════════
    // SSH options
    // ═══════════════════════════════════════════════════════════════════════════
    /// SSH protocol
    SshProto,
    /// SSH software
    SshSoftware,
    /// SSH HASSH
    SshHassh,
    /// SSH HASSH server
    SshHasshServer,

    // ═══════════════════════════════════════════════════════════════════════════
    // File options
    // ═══════════════════════════════════════════════════════════════════════════
    /// File data buffer
    FileData,
    /// Filename
    Filename,
    /// File extension
    Fileext,
    /// File magic
    Filemagic,
    /// File MD5
    FileMd5,
    /// File SHA1
    FileSha1,
    /// File SHA256
    FileSha256,
    /// File size
    Filesize(SizeMatch),
    /// File store
    Filestore,

    // ═══════════════════════════════════════════════════════════════════════════
    // Packet options
    // ═══════════════════════════════════════════════════════════════════════════
    /// TCP flags
    Flags(TcpFlags),
    /// TCP sequence number
    Seq(u32),
    /// TCP acknowledgment number
    Ack(u32),
    /// TCP window
    Window(SizeMatch),
    /// TTL
    Ttl(SizeMatch),
    /// IP ID
    Id(u16),
    /// IP type of service
    Tos(u8),
    /// IP options
    Ipopts(String),
    /// Fragment bits
    Fragbits(String),
    /// Fragment offset
    Fragoffset(SizeMatch),
    /// ICMP type
    IcmpType(SizeMatch),
    /// ICMP code
    IcmpCode(SizeMatch),
    /// ICMP ID
    IcmpId(u16),
    /// ICMP sequence
    IcmpSeq(u16),

    // ═══════════════════════════════════════════════════════════════════════════
    // Performance/behavior options
    // ═══════════════════════════════════════════════════════════════════════════
    /// Fast pattern hint
    FastPattern,
    /// Suppress alert
    Noalert,
    /// Tag session
    Tag {
        tag_type: String,
        count: u32,
        metric: String,
        direction: Option<String>,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // Transformation options
    // ═══════════════════════════════════════════════════════════════════════════
    /// Strip whitespace
    StripWhitespace,
    /// Compress whitespace
    CompressWhitespace,
    /// To lowercase
    ToLowercase,
    /// To uppercase
    ToUppercase,
    /// URL decode
    UrlDecode,
    /// Dotprefix
    DotPrefix,
    /// Xor decode
    Xor { key: Vec<u8> },

    // ═══════════════════════════════════════════════════════════════════════════
    // Application layer specific
    // ═══════════════════════════════════════════════════════════════════════════
    /// Application layer protocol
    AppLayerProtocol(String),
    /// Lua script
    LuaScript(String),

    /// Raw/unknown option for forward compatibility
    Raw { keyword: String, value: Option<String> },
}

/// Complete parsed rule
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    /// Internal rule ID
    pub id: u32,
    /// Whether rule is enabled
    pub enabled: bool,
    /// Rule action
    pub action: Action,
    /// Protocol
    pub protocol: Protocol,
    /// Source IP specification
    pub src_ip: IpSpec,
    /// Source port specification
    pub src_port: PortSpec,
    /// Traffic direction
    pub direction: Direction,
    /// Destination IP specification
    pub dst_ip: IpSpec,
    /// Destination port specification
    pub dst_port: PortSpec,
    /// Rule options
    pub options: Vec<RuleOption>,

    // Extracted metadata for quick access
    /// Signature ID
    pub sid: u32,
    /// Revision
    pub rev: u32,
    /// Alert message
    pub msg: String,
    /// Classification type
    pub classtype: Option<String>,
    /// Priority
    pub priority: u8,
    /// References
    pub references: Vec<Reference>,
    /// Source file
    pub source_file: Option<String>,
    /// Line number in source
    pub source_line: Option<u32>,
}

impl Default for Rule {
    fn default() -> Self {
        Self {
            id: 0,
            enabled: true,
            action: Action::Alert,
            protocol: Protocol::Any,
            src_ip: IpSpec::Any,
            src_port: PortSpec::Any,
            direction: Direction::ToServer,
            dst_ip: IpSpec::Any,
            dst_port: PortSpec::Any,
            options: Vec::new(),
            sid: 0,
            rev: 1,
            msg: String::new(),
            classtype: None,
            priority: 3,
            references: Vec::new(),
            source_file: None,
            source_line: None,
        }
    }
}

impl Rule {
    /// Check if rule has content patterns
    pub fn has_content(&self) -> bool {
        self.options.iter().any(|opt| matches!(opt, RuleOption::Content(_)))
    }

    /// Get all content patterns
    pub fn content_patterns(&self) -> Vec<&ContentMatch> {
        self.options
            .iter()
            .filter_map(|opt| {
                if let RuleOption::Content(cm) = opt {
                    Some(cm)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Get fast pattern (for Aho-Corasick pre-filter)
    pub fn fast_pattern(&self) -> Option<&ContentMatch> {
        // First look for explicit fast_pattern (must not be negated)
        for opt in &self.options {
            if let RuleOption::Content(cm) = opt {
                if cm.fast_pattern && !cm.negated {
                    return Some(cm);
                }
            }
        }
        // Otherwise use longest non-negated content
        self.content_patterns()
            .into_iter()
            .filter(|cm| !cm.negated)
            .max_by_key(|cm| cm.pattern.len())
    }

    /// Check if rule is for specific protocol
    pub fn is_protocol(&self, proto: Protocol) -> bool {
        self.protocol == proto || self.protocol == Protocol::Any
    }

    /// Get flow flags if present
    pub fn flow_flags(&self) -> Option<&FlowFlags> {
        self.options.iter().find_map(|opt| {
            if let RuleOption::Flow(flags) = opt {
                Some(flags)
            } else {
                None
            }
        })
    }

    /// Check if rule has HTTP keywords
    pub fn is_http_rule(&self) -> bool {
        self.protocol == Protocol::Http || self.options.iter().any(|opt| {
            matches!(
                opt,
                RuleOption::HttpUri
                    | RuleOption::HttpMethod
                    | RuleOption::HttpHeader
                    | RuleOption::HttpUserAgent
                    | RuleOption::HttpHost
                    | RuleOption::HttpClientBody
                    | RuleOption::HttpServerBody
            )
        })
    }

    /// Check if rule has DNS keywords
    pub fn is_dns_rule(&self) -> bool {
        self.protocol == Protocol::Dns || self.options.iter().any(|opt| {
            matches!(opt, RuleOption::DnsQuery | RuleOption::DnsAnswer)
        })
    }

    /// Check if rule has TLS keywords
    pub fn is_tls_rule(&self) -> bool {
        self.protocol == Protocol::Tls || self.options.iter().any(|opt| {
            matches!(
                opt,
                RuleOption::TlsSni
                    | RuleOption::TlsCertSubject
                    | RuleOption::Ja3Hash
                    | RuleOption::Ja3sHash
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_parse() {
        assert_eq!("alert".parse::<Action>().unwrap(), Action::Alert);
        assert_eq!("drop".parse::<Action>().unwrap(), Action::Drop);
        assert_eq!("REJECT".parse::<Action>().unwrap(), Action::Reject);
    }

    #[test]
    fn test_protocol_parse() {
        assert_eq!("tcp".parse::<Protocol>().unwrap(), Protocol::Tcp);
        assert_eq!("HTTP".parse::<Protocol>().unwrap(), Protocol::Http);
        assert_eq!("dns".parse::<Protocol>().unwrap(), Protocol::Dns);
    }

    #[test]
    fn test_rule_default() {
        let rule = Rule::default();
        assert_eq!(rule.action, Action::Alert);
        assert_eq!(rule.protocol, Protocol::Any);
        assert!(rule.enabled);
    }
}
