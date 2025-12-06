//! Suricata/Snort rule parser using nom
//!
//! Parses rule syntax:
//! action protocol src_ip src_port -> dst_ip dst_port (options)

use nom::{
    branch::alt,
    bytes::complete::{tag, tag_no_case, take_till, take_until, take_while1},
    character::complete::{char, digit1, multispace0, multispace1},
    combinator::{map, map_res, opt, recognize, value},
    multi::{separated_list0, separated_list1},
    sequence::{delimited, preceded, tuple},
    IResult,
};

use std::net::IpAddr;

use super::ast::*;

/// Parse error type
#[derive(Debug, Clone)]
pub struct ParseError {
    pub message: String,
    pub line: Option<u32>,
    pub position: Option<usize>,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Parse error: {}", self.message)?;
        if let Some(line) = self.line {
            write!(f, " at line {}", line)?;
        }
        Ok(())
    }
}

impl std::error::Error for ParseError {}

/// Parse a complete rule from string
pub fn parse_rule(input: &str) -> Result<Rule, ParseError> {
    let input = input.trim();

    // Skip comments and empty lines
    if input.is_empty() || input.starts_with('#') {
        return Err(ParseError {
            message: "Empty or comment line".into(),
            line: None,
            position: None,
        });
    }

    match parse_rule_internal(input) {
        Ok((remaining, rule)) => {
            if remaining.trim().is_empty() {
                Ok(rule)
            } else {
                Err(ParseError {
                    message: format!("Unexpected trailing content: {}", remaining),
                    line: None,
                    position: Some(input.len() - remaining.len()),
                })
            }
        }
        Err(e) => Err(ParseError {
            message: format!("Parse failed: {:?}", e),
            line: None,
            position: None,
        }),
    }
}

/// Internal parser entry point
fn parse_rule_internal(input: &str) -> IResult<&str, Rule> {
    let (input, _) = multispace0(input)?;
    let (input, action) = parse_action(input)?;
    let (input, _) = multispace1(input)?;
    let (input, protocol) = parse_protocol(input)?;
    let (input, _) = multispace1(input)?;
    let (input, src_ip) = parse_ip_spec(input)?;
    let (input, _) = multispace1(input)?;
    let (input, src_port) = parse_port_spec(input)?;
    let (input, _) = multispace1(input)?;
    let (input, direction) = parse_direction(input)?;
    let (input, _) = multispace1(input)?;
    let (input, dst_ip) = parse_ip_spec(input)?;
    let (input, _) = multispace1(input)?;
    let (input, dst_port) = parse_port_spec(input)?;
    let (input, _) = multispace0(input)?;
    let (input, options) = parse_options(input)?;

    // Extract metadata from options
    let sid = extract_sid(&options);
    let rev = extract_rev(&options);
    let msg = extract_msg(&options);
    let classtype = extract_classtype(&options);
    let priority = extract_priority(&options);
    let references = extract_references(&options);

    Ok((
        input,
        Rule {
            id: sid,
            enabled: true,
            action,
            protocol,
            src_ip,
            src_port,
            direction,
            dst_ip,
            dst_port,
            options,
            sid,
            rev,
            msg,
            classtype,
            priority,
            references,
            source_file: None,
            source_line: None,
        },
    ))
}

// ═══════════════════════════════════════════════════════════════════════════════
// Action parser
// ═══════════════════════════════════════════════════════════════════════════════

fn parse_action(input: &str) -> IResult<&str, Action> {
    alt((
        value(Action::Alert, tag_no_case("alert")),
        value(Action::Drop, tag_no_case("drop")),
        value(Action::Reject, tag_no_case("reject")),
        value(Action::Pass, tag_no_case("pass")),
        value(Action::Log, tag_no_case("log")),
    ))(input)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Protocol parser
// ═══════════════════════════════════════════════════════════════════════════════

fn parse_protocol(input: &str) -> IResult<&str, Protocol> {
    alt((
        value(Protocol::Tcp, tag_no_case("tcp")),
        value(Protocol::Udp, tag_no_case("udp")),
        value(Protocol::Icmp, tag_no_case("icmp")),
        value(Protocol::Http, tag_no_case("http")),
        value(Protocol::Dns, tag_no_case("dns")),
        value(Protocol::Tls, tag_no_case("tls")),
        value(Protocol::Tls, tag_no_case("ssl")),
        value(Protocol::Ssh, tag_no_case("ssh")),
        value(Protocol::Ftp, tag_no_case("ftp")),
        value(Protocol::Smtp, tag_no_case("smtp")),
        value(Protocol::Smb, tag_no_case("smb")),
        value(Protocol::Dcerpc, tag_no_case("dcerpc")),
        value(Protocol::Dhcp, tag_no_case("dhcp")),
        value(Protocol::Ntp, tag_no_case("ntp")),
        value(Protocol::Ip, tag_no_case("ip")),
        value(Protocol::Any, tag_no_case("any")),
    ))(input)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Direction parser
// ═══════════════════════════════════════════════════════════════════════════════

fn parse_direction(input: &str) -> IResult<&str, Direction> {
    alt((
        value(Direction::Both, tag("<>")),
        value(Direction::ToClient, tag("<-")),
        value(Direction::ToServer, tag("->")),
    ))(input)
}

// ═══════════════════════════════════════════════════════════════════════════════
// IP spec parser
// ═══════════════════════════════════════════════════════════════════════════════

fn parse_ip_spec(input: &str) -> IResult<&str, IpSpec> {
    alt((
        // Negated
        map(preceded(char('!'), parse_ip_spec_inner), |spec| {
            IpSpec::Negated(Box::new(spec))
        }),
        // List
        map(
            delimited(
                char('['),
                separated_list1(
                    tuple((multispace0, char(','), multispace0)),
                    parse_ip_spec_inner,
                ),
                char(']'),
            ),
            IpSpec::List,
        ),
        parse_ip_spec_inner,
    ))(input)
}

fn parse_ip_spec_inner(input: &str) -> IResult<&str, IpSpec> {
    alt((
        value(IpSpec::Any, tag_no_case("any")),
        // Variable ($HOME_NET)
        map(
            preceded(char('$'), take_while1(|c: char| c.is_alphanumeric() || c == '_')),
            |name: &str| IpSpec::Var(name.to_string()),
        ),
        // CIDR notation
        map_res(
            recognize(tuple((
                take_while1(|c: char| c.is_ascii_digit() || c == '.' || c == ':'),
                char('/'),
                digit1,
            ))),
            |s: &str| -> Result<IpSpec, &'static str> {
                let parts: Vec<&str> = s.split('/').collect();
                if parts.len() != 2 {
                    return Err("Invalid CIDR");
                }
                let ip: IpAddr = parts[0].parse().map_err(|_| "Invalid IP")?;
                let prefix: u8 = parts[1].parse().map_err(|_| "Invalid prefix")?;
                Ok(IpSpec::Cidr(ip, prefix))
            },
        ),
        // Single IP
        map_res(
            take_while1(|c: char| c.is_ascii_digit() || c == '.' || c == ':'),
            |s: &str| -> Result<IpSpec, &'static str> {
                let ip: IpAddr = s.parse().map_err(|_| "Invalid IP")?;
                Ok(IpSpec::Single(ip))
            },
        ),
    ))(input)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Port spec parser
// ═══════════════════════════════════════════════════════════════════════════════

fn parse_port_spec(input: &str) -> IResult<&str, PortSpec> {
    alt((
        // Negated
        map(preceded(char('!'), parse_port_spec_inner), |spec| {
            PortSpec::Negated(Box::new(spec))
        }),
        // List
        map(
            delimited(
                char('['),
                separated_list1(
                    tuple((multispace0, char(','), multispace0)),
                    parse_port_spec_inner,
                ),
                char(']'),
            ),
            PortSpec::List,
        ),
        parse_port_spec_inner,
    ))(input)
}

fn parse_port_spec_inner(input: &str) -> IResult<&str, PortSpec> {
    alt((
        value(PortSpec::Any, tag_no_case("any")),
        // Variable
        map(
            preceded(char('$'), take_while1(|c: char| c.is_alphanumeric() || c == '_')),
            |name: &str| PortSpec::Var(name.to_string()),
        ),
        // Port range (1024:65535)
        map_res(
            recognize(tuple((digit1, char(':'), digit1))),
            |s: &str| -> Result<PortSpec, &'static str> {
                let parts: Vec<&str> = s.split(':').collect();
                if parts.len() != 2 {
                    return Err("Invalid port range");
                }
                let start: u16 = parts[0].parse().map_err(|_| "Invalid port")?;
                let end: u16 = parts[1].parse().map_err(|_| "Invalid port")?;
                Ok(PortSpec::Range(start, end))
            },
        ),
        // Single port
        map_res(digit1, |s: &str| -> Result<PortSpec, &'static str> {
            let port: u16 = s.parse().map_err(|_| "Invalid port")?;
            Ok(PortSpec::Single(port))
        }),
    ))(input)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Options parser
// ═══════════════════════════════════════════════════════════════════════════════

fn parse_options(input: &str) -> IResult<&str, Vec<RuleOption>> {
    delimited(
        tuple((multispace0, char('('), multispace0)),
        separated_list0(
            tuple((multispace0, char(';'), multispace0)),
            parse_single_option,
        ),
        tuple((multispace0, opt(char(';')), multispace0, char(')'))),
    )(input)
}

fn parse_single_option(input: &str) -> IResult<&str, RuleOption> {
    let (input, keyword) = take_while1(|c: char| c.is_alphanumeric() || c == '_' || c == '.')(input)?;
    let (input, _) = multispace0(input)?;

    // Check if there's a value
    let (input, value) = opt(preceded(
        tuple((char(':'), multispace0)),
        parse_option_value,
    ))(input)?;

    let option = match keyword.to_lowercase().as_str() {
        // Metadata
        "msg" => RuleOption::Msg(value.unwrap_or_default().trim_matches('"').to_string()),
        "sid" => RuleOption::Sid(value.unwrap_or_default().parse().unwrap_or(0)),
        "rev" => RuleOption::Rev(value.unwrap_or_default().parse().unwrap_or(1)),
        "gid" => RuleOption::Gid(value.unwrap_or_default().parse().unwrap_or(1)),
        "classtype" => RuleOption::Classtype(value.unwrap_or_default().to_string()),
        "priority" => RuleOption::Priority(value.unwrap_or_default().parse().unwrap_or(3)),
        "reference" => {
            let v = value.unwrap_or_default();
            let parts: Vec<&str> = v.splitn(2, ',').collect();
            RuleOption::Reference(Reference {
                ref_type: parts.first().unwrap_or(&"").to_string(),
                ref_id: parts.get(1).unwrap_or(&"").to_string(),
            })
        }
        "metadata" => {
            let v = value.unwrap_or_default();
            let metadata = parse_metadata_value(&v);
            RuleOption::Metadata(metadata)
        }

        // Content
        "content" => {
            let v = value.unwrap_or_default();
            let (negated, pattern) = parse_content_value(&v);
            RuleOption::Content(ContentMatch {
                pattern,
                negated,
                ..Default::default()
            })
        }
        "nocase" => {
            // This modifies the previous content, but we handle it in post-processing
            RuleOption::Raw { keyword: "nocase".into(), value: None }
        }
        "offset" => RuleOption::Raw { keyword: "offset".into(), value: value.map(String::from) },
        "depth" => RuleOption::Raw { keyword: "depth".into(), value: value.map(String::from) },
        "distance" => RuleOption::Raw { keyword: "distance".into(), value: value.map(String::from) },
        "within" => RuleOption::Raw { keyword: "within".into(), value: value.map(String::from) },
        "fast_pattern" => RuleOption::FastPattern,
        "rawbytes" => RuleOption::Raw { keyword: "rawbytes".into(), value: None },

        // PCRE
        "pcre" => {
            let v = value.unwrap_or_default();
            let pcre = parse_pcre_value(&v);
            RuleOption::Pcre(pcre)
        }

        // Flow
        "flow" => {
            let v = value.unwrap_or_default();
            let flags = parse_flow_value(&v);
            RuleOption::Flow(flags)
        }
        "flowbits" => {
            let v = value.unwrap_or_default();
            let op = parse_flowbits_value(&v);
            RuleOption::Flowbits(op)
        }

        // Size
        "dsize" => {
            let v = value.unwrap_or_default();
            let size = parse_size_value(&v);
            RuleOption::Dsize(size)
        }

        // Threshold
        "threshold" => {
            let v = value.unwrap_or_default();
            if let Some(spec) = parse_threshold_value(&v) {
                RuleOption::Threshold(spec)
            } else {
                RuleOption::Raw { keyword: "threshold".into(), value: value.map(String::from) }
            }
        }
        "detection_filter" => {
            let v = value.unwrap_or_default();
            if let Some(spec) = parse_threshold_value(&v) {
                RuleOption::DetectionFilter(spec)
            } else {
                RuleOption::Raw { keyword: "detection_filter".into(), value: value.map(String::from) }
            }
        }

        // HTTP
        "http_uri" | "http.uri" => RuleOption::HttpUri,
        "http_raw_uri" | "http.uri.raw" => RuleOption::HttpRawUri,
        "http_method" | "http.method" => RuleOption::HttpMethod,
        "http_header" | "http.header" => RuleOption::HttpHeader,
        "http_raw_header" | "http.header.raw" => RuleOption::HttpRawHeader,
        "http_cookie" | "http.cookie" => RuleOption::HttpCookie,
        "http_user_agent" | "http.user_agent" => RuleOption::HttpUserAgent,
        "http_host" | "http.host" => RuleOption::HttpHost,
        "http_client_body" | "http.request_body" => RuleOption::HttpClientBody,
        "http_server_body" | "http.response_body" => RuleOption::HttpServerBody,
        "http_stat_code" | "http.stat_code" => RuleOption::HttpStatCode,
        "http_stat_msg" | "http.stat_msg" => RuleOption::HttpStatMsg,

        // DNS
        "dns_query" | "dns.query" => RuleOption::DnsQuery,
        "dns.opcode" => RuleOption::DnsOpcode(value.unwrap_or_default().parse().unwrap_or(0)),

        // TLS
        "tls_sni" | "tls.sni" => RuleOption::TlsSni,
        "tls_cert_subject" | "tls.cert_subject" => RuleOption::TlsCertSubject,
        "tls_cert_issuer" | "tls.cert_issuer" => RuleOption::TlsCertIssuer,
        "ja3_hash" | "ja3.hash" => RuleOption::Ja3Hash,
        "ja3_string" | "ja3.string" => RuleOption::Ja3String,
        "ja3s_hash" | "ja3s.hash" => RuleOption::Ja3sHash,
        "ja3s_string" | "ja3s.string" => RuleOption::Ja3sString,

        // SSH
        "ssh.proto" => RuleOption::SshProto,
        "ssh.software" => RuleOption::SshSoftware,
        "ssh.hassh" => RuleOption::SshHassh,
        "ssh.hassh.server" => RuleOption::SshHasshServer,

        // File
        "file_data" | "file.data" => RuleOption::FileData,
        "filename" => RuleOption::Filename,
        "fileext" => RuleOption::Fileext,

        // Packet
        "flags" => {
            let v = value.unwrap_or_default();
            let flags = parse_tcp_flags(&v);
            RuleOption::Flags(flags)
        }
        "ttl" => {
            let v = value.unwrap_or_default();
            let size = parse_size_value(&v);
            RuleOption::Ttl(size)
        }
        "itype" => {
            let v = value.unwrap_or_default();
            let size = parse_size_value(&v);
            RuleOption::IcmpType(size)
        }
        "icode" => {
            let v = value.unwrap_or_default();
            let size = parse_size_value(&v);
            RuleOption::IcmpCode(size)
        }

        // Performance
        "noalert" => RuleOption::Noalert,

        // Unknown/raw
        _ => RuleOption::Raw {
            keyword: keyword.to_string(),
            value: value.map(String::from),
        },
    };

    Ok((input, option))
}

/// Parse option value (handles quoted strings and regular values)
fn parse_option_value(input: &str) -> IResult<&str, &str> {
    alt((
        // Quoted string
        delimited(char('"'), take_until("\""), char('"')),
        // Unquoted value (until semicolon or closing paren)
        take_till(|c| c == ';' || c == ')'),
    ))(input)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Value parsers
// ═══════════════════════════════════════════════════════════════════════════════

/// Parse content value including hex escapes like |00 01 02|
fn parse_content_value(input: &str) -> (bool, Vec<u8>) {
    let input = input.trim();
    let (negated, input) = if input.starts_with('!') {
        (true, &input[1..])
    } else {
        (false, input)
    };

    let input = input.trim().trim_matches('"');
    let mut result = Vec::new();
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '|' => {
                // Hex mode
                let mut hex_str = String::new();
                while let Some(&hc) = chars.peek() {
                    if hc == '|' {
                        chars.next();
                        break;
                    }
                    if !hc.is_whitespace() {
                        hex_str.push(hc);
                    }
                    chars.next();
                }
                // Parse hex bytes
                let hex_bytes: Vec<u8> = hex_str
                    .as_bytes()
                    .chunks(2)
                    .filter_map(|chunk| {
                        if chunk.len() == 2 {
                            u8::from_str_radix(std::str::from_utf8(chunk).unwrap_or(""), 16).ok()
                        } else {
                            None
                        }
                    })
                    .collect();
                result.extend(hex_bytes);
            }
            '\\' => {
                if let Some(esc) = chars.next() {
                    match esc {
                        'n' => result.push(b'\n'),
                        'r' => result.push(b'\r'),
                        't' => result.push(b'\t'),
                        '\\' => result.push(b'\\'),
                        '"' => result.push(b'"'),
                        ';' => result.push(b';'),
                        ':' => result.push(b':'),
                        _ => {
                            result.push(b'\\');
                            result.push(esc as u8);
                        }
                    }
                }
            }
            _ => result.push(c as u8),
        }
    }

    (negated, result)
}

/// Parse PCRE value
fn parse_pcre_value(input: &str) -> PcreMatch {
    let input = input.trim().trim_matches('"');
    let negated = input.starts_with('!');
    let input = if negated { &input[1..] } else { input };

    // Format: /pattern/flags
    if let Some(start) = input.find('/') {
        let rest = &input[start + 1..];
        if let Some(end) = rest.rfind('/') {
            let pattern = &rest[..end];
            let flags = &rest[end + 1..];
            return PcreMatch {
                pattern: pattern.to_string(),
                flags: flags.to_string(),
                negated,
                relative: flags.contains('R'),
            };
        }
    }

    PcreMatch {
        pattern: input.to_string(),
        flags: String::new(),
        negated,
        relative: false,
    }
}

/// Parse flow value
fn parse_flow_value(input: &str) -> FlowFlags {
    let mut flags = FlowFlags::default();
    let input = input.to_lowercase();

    for part in input.split(',') {
        let part = part.trim();
        match part {
            "to_server" | "toserver" => flags.to_server = true,
            "to_client" | "toclient" => flags.to_client = true,
            "from_server" | "fromserver" => flags.from_server = true,
            "from_client" | "fromclient" => flags.from_client = true,
            "established" => flags.established = true,
            "not_established" => flags.not_established = true,
            "stateless" => flags.stateless = true,
            "only_stream" => flags.only_stream = true,
            "no_stream" => flags.no_stream = true,
            "only_frag" => flags.only_frag = true,
            "no_frag" => flags.no_frag = true,
            _ => {}
        }
    }

    flags
}

/// Parse flowbits value
fn parse_flowbits_value(input: &str) -> FlowbitsOp {
    let parts: Vec<&str> = input.splitn(2, ',').collect();
    let operation = parts.first().unwrap_or(&"").trim();
    let name = parts.get(1).unwrap_or(&"").trim().to_string();

    match operation.to_lowercase().as_str() {
        "set" => FlowbitsOp::Set(name),
        "unset" => FlowbitsOp::Unset(name),
        "toggle" => FlowbitsOp::Toggle(name),
        "isset" => FlowbitsOp::IsSet(name),
        "isnotset" => FlowbitsOp::IsNotSet(name),
        "noalert" => FlowbitsOp::NoAlert,
        _ => FlowbitsOp::Set(input.to_string()),
    }
}

/// Parse size value (for dsize, ttl, etc.)
fn parse_size_value(input: &str) -> SizeMatch {
    let input = input.trim();

    // Range: 100<>200
    if input.contains("<>") {
        let parts: Vec<&str> = input.split("<>").collect();
        if parts.len() == 2 {
            return SizeMatch {
                operator: CompareOp::Range,
                value: parts[0].trim().parse().unwrap_or(0),
                value2: parts[1].trim().parse().ok(),
            };
        }
    }

    // Comparison operators
    let (op, val_str) = if input.starts_with(">=") {
        (CompareOp::GreaterOrEqual, &input[2..])
    } else if input.starts_with("<=") {
        (CompareOp::LessOrEqual, &input[2..])
    } else if input.starts_with("!=") {
        (CompareOp::NotEqual, &input[2..])
    } else if input.starts_with('>') {
        (CompareOp::GreaterThan, &input[1..])
    } else if input.starts_with('<') {
        (CompareOp::LessThan, &input[1..])
    } else if input.starts_with('=') {
        (CompareOp::Equal, &input[1..])
    } else {
        (CompareOp::Equal, input)
    };

    SizeMatch {
        operator: op,
        value: val_str.trim().parse().unwrap_or(0),
        value2: None,
    }
}

/// Parse threshold value
fn parse_threshold_value(input: &str) -> Option<ThresholdSpec> {
    let input = input.to_lowercase();
    let mut threshold_type = ThresholdType::Threshold;
    let mut track = TrackBy::BySrc;
    let mut count = 1;
    let mut seconds = 60;

    for part in input.split(',') {
        let part = part.trim();
        if part.starts_with("type") {
            let val = part.split_whitespace().nth(1).unwrap_or("");
            threshold_type = match val {
                "limit" => ThresholdType::Limit,
                "threshold" => ThresholdType::Threshold,
                "both" => ThresholdType::Both,
                _ => ThresholdType::Threshold,
            };
        } else if part.starts_with("track") {
            let val = part.split_whitespace().nth(1).unwrap_or("");
            track = match val {
                "by_src" => TrackBy::BySrc,
                "by_dst" => TrackBy::ByDst,
                "by_rule" => TrackBy::ByRule,
                "by_both" => TrackBy::ByBoth,
                _ => TrackBy::BySrc,
            };
        } else if part.starts_with("count") {
            count = part.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(1);
        } else if part.starts_with("seconds") {
            seconds = part.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(60);
        }
    }

    Some(ThresholdSpec {
        threshold_type,
        track,
        count,
        seconds,
    })
}

/// Parse TCP flags
fn parse_tcp_flags(input: &str) -> TcpFlags {
    let mut flags = TcpFlags::default();
    let input = input.to_uppercase();

    for c in input.chars() {
        match c {
            'F' => flags.fin = Some(true),
            'S' => flags.syn = Some(true),
            'R' => flags.rst = Some(true),
            'P' => flags.psh = Some(true),
            'A' => flags.ack = Some(true),
            'U' => flags.urg = Some(true),
            'E' => flags.ece = Some(true),
            'C' => flags.cwr = Some(true),
            '+' => flags.match_all = true,
            '*' => flags.match_any = true,
            '0' => {} // All flags off
            _ => {}
        }
    }

    flags
}

/// Parse metadata value
fn parse_metadata_value(input: &str) -> Vec<Metadata> {
    input
        .split(',')
        .filter_map(|pair| {
            let parts: Vec<&str> = pair.trim().splitn(2, ' ').collect();
            if parts.len() >= 1 {
                Some(Metadata {
                    key: parts[0].trim().to_string(),
                    value: parts.get(1).unwrap_or(&"").trim().to_string(),
                })
            } else {
                None
            }
        })
        .collect()
}

// ═══════════════════════════════════════════════════════════════════════════════
// Metadata extraction helpers
// ═══════════════════════════════════════════════════════════════════════════════

fn extract_sid(options: &[RuleOption]) -> u32 {
    options.iter().find_map(|opt| {
        if let RuleOption::Sid(sid) = opt {
            Some(*sid)
        } else {
            None
        }
    }).unwrap_or(0)
}

fn extract_rev(options: &[RuleOption]) -> u32 {
    options.iter().find_map(|opt| {
        if let RuleOption::Rev(rev) = opt {
            Some(*rev)
        } else {
            None
        }
    }).unwrap_or(1)
}

fn extract_msg(options: &[RuleOption]) -> String {
    options.iter().find_map(|opt| {
        if let RuleOption::Msg(msg) = opt {
            Some(msg.clone())
        } else {
            None
        }
    }).unwrap_or_default()
}

fn extract_classtype(options: &[RuleOption]) -> Option<String> {
    options.iter().find_map(|opt| {
        if let RuleOption::Classtype(ct) = opt {
            Some(ct.clone())
        } else {
            None
        }
    })
}

fn extract_priority(options: &[RuleOption]) -> u8 {
    options.iter().find_map(|opt| {
        if let RuleOption::Priority(p) = opt {
            Some(*p)
        } else {
            None
        }
    }).unwrap_or(3)
}

fn extract_references(options: &[RuleOption]) -> Vec<Reference> {
    options.iter().filter_map(|opt| {
        if let RuleOption::Reference(r) = opt {
            Some(r.clone())
        } else {
            None
        }
    }).collect()
}

/// Post-process options to apply modifiers to content matches
pub fn apply_content_modifiers(mut rule: Rule) -> Rule {
    let mut new_options = Vec::new();
    let mut current_content: Option<ContentMatch> = None;

    for opt in rule.options {
        match opt {
            RuleOption::Content(cm) => {
                // Push previous content if exists
                if let Some(prev) = current_content.take() {
                    new_options.push(RuleOption::Content(prev));
                }
                current_content = Some(cm);
            }
            RuleOption::Raw { ref keyword, ref value } => {
                if let Some(ref mut cm) = current_content {
                    match keyword.as_str() {
                        "nocase" => cm.nocase = true,
                        "rawbytes" => cm.rawbytes = true,
                        "offset" => cm.offset = value.as_ref().and_then(|v| v.trim().parse().ok()),
                        "depth" => cm.depth = value.as_ref().and_then(|v| v.trim().parse().ok()),
                        "distance" => cm.distance = value.as_ref().and_then(|v| v.trim().parse().ok()),
                        "within" => cm.within = value.as_ref().and_then(|v| v.trim().parse().ok()),
                        _ => new_options.push(opt),
                    }
                } else {
                    new_options.push(opt);
                }
            }
            RuleOption::FastPattern => {
                if let Some(ref mut cm) = current_content {
                    cm.fast_pattern = true;
                } else {
                    new_options.push(opt);
                }
            }
            _ => {
                new_options.push(opt);
            }
        }
    }

    // Push last content
    if let Some(cm) = current_content {
        new_options.push(RuleOption::Content(cm));
    }

    rule.options = new_options;
    rule
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_rule() {
        let rule_str = r#"alert tcp any any -> any 80 (msg:"Test rule"; sid:1000001; rev:1;)"#;
        let rule = parse_rule(rule_str).unwrap();

        assert_eq!(rule.action, Action::Alert);
        assert_eq!(rule.protocol, Protocol::Tcp);
        assert_eq!(rule.src_ip, IpSpec::Any);
        assert_eq!(rule.src_port, PortSpec::Any);
        assert_eq!(rule.direction, Direction::ToServer);
        assert_eq!(rule.dst_port, PortSpec::Single(80));
        assert_eq!(rule.sid, 1000001);
        assert_eq!(rule.msg, "Test rule");
    }

    #[test]
    fn test_parse_content_rule() {
        let rule_str = r#"alert http any any -> any any (msg:"SQL Injection"; content:"UNION SELECT"; nocase; sid:1000002;)"#;
        let rule = parse_rule(rule_str).unwrap();
        let rule = apply_content_modifiers(rule);

        assert_eq!(rule.protocol, Protocol::Http);
        assert!(rule.has_content());

        let content = rule.content_patterns();
        assert_eq!(content.len(), 1);
        assert_eq!(content[0].pattern, b"UNION SELECT");
        assert!(content[0].nocase);
    }

    #[test]
    fn test_parse_hex_content() {
        let rule_str = r#"alert tcp any any -> any any (msg:"Hex test"; content:"|00 01 02|test|03 04|"; sid:1000003;)"#;
        let rule = parse_rule(rule_str).unwrap();

        let content = rule.content_patterns();
        assert_eq!(content.len(), 1);
        assert_eq!(content[0].pattern, vec![0x00, 0x01, 0x02, b't', b'e', b's', b't', 0x03, 0x04]);
    }

    #[test]
    fn test_parse_flow() {
        let rule_str = r#"alert tcp any any -> any 22 (msg:"SSH"; flow:to_server,established; sid:1000004;)"#;
        let rule = parse_rule(rule_str).unwrap();

        let flow = rule.flow_flags().unwrap();
        assert!(flow.to_server);
        assert!(flow.established);
    }

    #[test]
    fn test_parse_pcre() {
        let rule_str = r#"alert http any any -> any any (msg:"PCRE test"; pcre:"/test.*pattern/i"; sid:1000005;)"#;
        let rule = parse_rule(rule_str).unwrap();

        let pcre = rule.options.iter().find_map(|opt| {
            if let RuleOption::Pcre(p) = opt { Some(p) } else { None }
        }).unwrap();

        assert_eq!(pcre.pattern, "test.*pattern");
        assert_eq!(pcre.flags, "i");
    }

    #[test]
    fn test_parse_ip_spec() {
        // CIDR
        let (_, spec) = parse_ip_spec("192.168.1.0/24").unwrap();
        assert!(matches!(spec, IpSpec::Cidr(_, 24)));

        // Variable
        let (_, spec) = parse_ip_spec("$HOME_NET").unwrap();
        assert!(matches!(spec, IpSpec::Var(ref name) if name == "HOME_NET"));

        // Negated
        let (_, spec) = parse_ip_spec("!192.168.1.1").unwrap();
        assert!(matches!(spec, IpSpec::Negated(_)));
    }
}
