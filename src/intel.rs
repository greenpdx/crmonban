use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;
use tracing::{debug, info, warn};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

use crate::config::IntelConfig;
use crate::models::AttackerIntel;

/// Intelligence gatherer for collecting information about attackers
pub struct IntelGatherer {
    config: IntelConfig,
    client: Client,
}

impl IntelGatherer {
    /// Create a new intelligence gatherer
    pub fn new(config: IntelConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .user_agent("crmonban/0.1")
            .build()?;

        Ok(Self { config, client })
    }

    /// Gather all available intelligence for an IP
    pub async fn gather(&self, ip: &str) -> Result<AttackerIntel> {
        info!("Gathering intelligence for IP: {}", ip);
        let mut intel = AttackerIntel::new(ip.to_string());

        // Run lookups concurrently
        let (geoip_result, rdns_result, whois_result) = tokio::join!(
            self.lookup_geoip(ip),
            self.lookup_rdns(ip),
            self.lookup_whois(ip)
        );

        // GeoIP
        if self.config.geoip_enabled {
            match geoip_result {
                Ok(geo) => {
                    intel.country = geo.country;
                    intel.country_code = geo.country_code;
                    intel.city = geo.city;
                    intel.region = geo.region;
                    intel.latitude = geo.latitude;
                    intel.longitude = geo.longitude;
                    intel.timezone = geo.timezone;
                    intel.asn = geo.asn;
                    intel.as_org = geo.as_org;
                    intel.isp = geo.isp;
                    intel.is_tor_exit = geo.is_tor;
                    intel.is_vpn = geo.is_vpn;
                    intel.is_proxy = geo.is_proxy;
                    intel.is_hosting = geo.is_hosting;
                }
                Err(e) => warn!("GeoIP lookup failed for {}: {}", ip, e),
            }
        }

        // Reverse DNS
        if self.config.rdns_enabled {
            match rdns_result {
                Ok(rdns) => intel.reverse_dns = Some(rdns),
                Err(e) => debug!("Reverse DNS lookup failed for {}: {}", ip, e),
            }
        }

        // WHOIS
        if self.config.whois_enabled {
            match whois_result {
                Ok(whois) => {
                    intel.whois_org = whois.org;
                    intel.whois_registrar = whois.registrar;
                    intel.whois_abuse_contact = whois.abuse_contact;
                    intel.whois_raw = whois.raw;
                }
                Err(e) => debug!("WHOIS lookup failed for {}: {}", ip, e),
            }
        }

        // Shodan (if API key provided)
        if let Some(ref api_key) = self.config.shodan_api_key {
            match self.lookup_shodan(ip, api_key).await {
                Ok(shodan) => {
                    intel.open_ports = shodan.ports;
                    intel.hostnames = shodan.hostnames;
                    intel.shodan_tags = shodan.tags;
                }
                Err(e) => debug!("Shodan lookup failed for {}: {}", ip, e),
            }
        }

        // AbuseIPDB (if API key provided)
        if let Some(ref api_key) = self.config.abuseipdb_api_key {
            match self.lookup_abuseipdb(ip, api_key).await {
                Ok(abuse) => {
                    intel.threat_score = abuse.abuse_confidence_score;
                    if intel.isp.is_none() {
                        intel.isp = abuse.isp;
                    }
                }
                Err(e) => debug!("AbuseIPDB lookup failed for {}: {}", ip, e),
            }
        }

        Ok(intel)
    }

    /// Lookup GeoIP information using ip-api.com (free, no API key needed)
    async fn lookup_geoip(&self, ip: &str) -> Result<GeoIpResponse> {
        let url = format!(
            "http://ip-api.com/json/{}?fields=status,message,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org,as,asname,proxy,hosting",
            ip
        );

        let resp: IpApiResponse = self.client.get(&url).send().await?.json().await?;

        if resp.status != "success" {
            anyhow::bail!("GeoIP lookup failed: {}", resp.message.unwrap_or_default());
        }

        Ok(GeoIpResponse {
            country: resp.country,
            country_code: resp.country_code,
            city: resp.city,
            region: resp.region_name,
            latitude: resp.lat,
            longitude: resp.lon,
            timezone: resp.timezone,
            asn: resp.r#as.as_ref().and_then(|s| {
                s.split_whitespace()
                    .next()
                    .and_then(|asn| asn.trim_start_matches("AS").parse().ok())
            }),
            as_org: resp.asname,
            isp: resp.isp,
            is_tor: None, // ip-api doesn't provide this
            is_vpn: None,
            is_proxy: resp.proxy,
            is_hosting: resp.hosting,
        })
    }

    /// Lookup reverse DNS
    async fn lookup_rdns(&self, ip: &str) -> Result<String> {
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

        let ip_addr: IpAddr = ip.parse().context("Invalid IP address")?;

        let response = resolver.reverse_lookup(ip_addr).await?;

        response
            .iter()
            .next()
            .map(|name| name.to_string().trim_end_matches('.').to_string())
            .ok_or_else(|| anyhow::anyhow!("No reverse DNS found"))
    }

    /// Lookup WHOIS information using whoisjson.com (limited free tier)
    async fn lookup_whois(&self, ip: &str) -> Result<WhoisResponse> {
        // Use RDAP for IP WHOIS (more reliable and structured)
        let url = format!("https://rdap.arin.net/registry/ip/{}", ip);

        let resp = self.client.get(&url).send().await?;

        if !resp.status().is_success() {
            // Try RIPE for non-ARIN IPs
            let url = format!("https://rdap.db.ripe.net/ip/{}", ip);
            let resp = self.client.get(&url).send().await?;

            if !resp.status().is_success() {
                anyhow::bail!("WHOIS lookup failed");
            }

            let rdap: RdapResponse = resp.json().await?;
            return Ok(self.parse_rdap(rdap));
        }

        let rdap: RdapResponse = resp.json().await?;
        Ok(self.parse_rdap(rdap))
    }

    fn parse_rdap(&self, rdap: RdapResponse) -> WhoisResponse {
        let mut org = None;
        let mut abuse_contact = None;
        let registrar = rdap.name.clone();

        // Extract organization and abuse contact from entities
        if let Some(entities) = &rdap.entities {
            for entity in entities {
                if let Some(roles) = &entity.roles {
                    if roles.contains(&"registrant".to_string()) {
                        if let Some(vcard) = &entity.vcard_array {
                            org = extract_vcard_org(vcard);
                        }
                    }
                    if roles.contains(&"abuse".to_string()) {
                        if let Some(vcard) = &entity.vcard_array {
                            abuse_contact = extract_vcard_email(vcard);
                        }
                    }
                }
            }
        }

        WhoisResponse {
            org,
            registrar,
            abuse_contact,
            raw: Some(serde_json::to_string_pretty(&rdap).unwrap_or_default()),
        }
    }

    /// Lookup Shodan information
    async fn lookup_shodan(&self, ip: &str, api_key: &str) -> Result<ShodanResponse> {
        let url = format!("https://api.shodan.io/shodan/host/{}?key={}", ip, api_key);

        let resp: ShodanApiResponse = self.client.get(&url).send().await?.json().await?;

        Ok(ShodanResponse {
            ports: resp.ports,
            hostnames: resp.hostnames,
            tags: resp.tags,
        })
    }

    /// Lookup AbuseIPDB information
    async fn lookup_abuseipdb(&self, ip: &str, api_key: &str) -> Result<AbuseIpDbResponse> {
        let url = format!(
            "https://api.abuseipdb.com/api/v2/check?ipAddress={}&maxAgeInDays=90",
            ip
        );

        let resp: AbuseIpDbApiResponse = self
            .client
            .get(&url)
            .header("Key", api_key)
            .header("Accept", "application/json")
            .send()
            .await?
            .json()
            .await?;

        Ok(AbuseIpDbResponse {
            abuse_confidence_score: resp.data.abuse_confidence_score,
            isp: resp.data.isp,
        })
    }
}

// Response types for various APIs

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct IpApiResponse {
    status: String,
    message: Option<String>,
    country: Option<String>,
    #[serde(rename = "countryCode")]
    country_code: Option<String>,
    region: Option<String>,
    #[serde(rename = "regionName")]
    region_name: Option<String>,
    city: Option<String>,
    lat: Option<f64>,
    lon: Option<f64>,
    timezone: Option<String>,
    isp: Option<String>,
    org: Option<String>,
    r#as: Option<String>,
    asname: Option<String>,
    proxy: Option<bool>,
    hosting: Option<bool>,
}

struct GeoIpResponse {
    country: Option<String>,
    country_code: Option<String>,
    city: Option<String>,
    region: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
    timezone: Option<String>,
    asn: Option<u32>,
    as_org: Option<String>,
    isp: Option<String>,
    is_tor: Option<bool>,
    is_vpn: Option<bool>,
    is_proxy: Option<bool>,
    is_hosting: Option<bool>,
}

struct WhoisResponse {
    org: Option<String>,
    registrar: Option<String>,
    abuse_contact: Option<String>,
    raw: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct RdapResponse {
    name: Option<String>,
    entities: Option<Vec<RdapEntity>>,
}

#[derive(Debug, Deserialize, Serialize)]
struct RdapEntity {
    roles: Option<Vec<String>>,
    #[serde(rename = "vcardArray")]
    vcard_array: Option<serde_json::Value>,
}

struct ShodanResponse {
    ports: Option<Vec<u16>>,
    hostnames: Option<Vec<String>>,
    tags: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct ShodanApiResponse {
    ports: Option<Vec<u16>>,
    hostnames: Option<Vec<String>>,
    tags: Option<Vec<String>>,
}

struct AbuseIpDbResponse {
    abuse_confidence_score: Option<u32>,
    isp: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AbuseIpDbApiResponse {
    data: AbuseIpDbData,
}

#[derive(Debug, Deserialize)]
struct AbuseIpDbData {
    #[serde(rename = "abuseConfidenceScore")]
    abuse_confidence_score: Option<u32>,
    isp: Option<String>,
}

// Helper functions for parsing vCard data from RDAP

fn extract_vcard_org(vcard: &serde_json::Value) -> Option<String> {
    if let Some(arr) = vcard.as_array() {
        if arr.len() > 1 {
            if let Some(props) = arr[1].as_array() {
                for prop in props {
                    if let Some(prop_arr) = prop.as_array() {
                        if prop_arr.len() >= 4 {
                            if prop_arr[0].as_str() == Some("org") {
                                return prop_arr[3].as_str().map(|s| s.to_string());
                            }
                            if prop_arr[0].as_str() == Some("fn") {
                                return prop_arr[3].as_str().map(|s| s.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

fn extract_vcard_email(vcard: &serde_json::Value) -> Option<String> {
    if let Some(arr) = vcard.as_array() {
        if arr.len() > 1 {
            if let Some(props) = arr[1].as_array() {
                for prop in props {
                    if let Some(prop_arr) = prop.as_array() {
                        if prop_arr.len() >= 4 && prop_arr[0].as_str() == Some("email") {
                            return prop_arr[3].as_str().map(|s| s.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

/// Format intelligence for display
pub fn format_intel(intel: &AttackerIntel) -> String {
    let mut output = String::new();

    output.push_str(&format!("IP: {}\n", intel.ip));

    if let Some(ref gathered) = intel.gathered_at {
        output.push_str(&format!("Gathered: {}\n", gathered.format("%Y-%m-%d %H:%M:%S UTC")));
    }

    output.push_str("\n--- Location ---\n");
    if let Some(ref country) = intel.country {
        output.push_str(&format!(
            "Country: {} ({})\n",
            country,
            intel.country_code.as_deref().unwrap_or("??")
        ));
    }
    if let Some(ref city) = intel.city {
        output.push_str(&format!(
            "City: {}{}\n",
            city,
            intel.region.as_ref().map(|r| format!(", {}", r)).unwrap_or_default()
        ));
    }
    if let (Some(lat), Some(lon)) = (intel.latitude, intel.longitude) {
        output.push_str(&format!("Coordinates: {:.4}, {:.4}\n", lat, lon));
    }
    if let Some(ref tz) = intel.timezone {
        output.push_str(&format!("Timezone: {}\n", tz));
    }

    output.push_str("\n--- Network ---\n");
    if let Some(asn) = intel.asn {
        output.push_str(&format!(
            "ASN: AS{}{}\n",
            asn,
            intel.as_org.as_ref().map(|o| format!(" ({})", o)).unwrap_or_default()
        ));
    }
    if let Some(ref isp) = intel.isp {
        output.push_str(&format!("ISP: {}\n", isp));
    }
    if let Some(ref rdns) = intel.reverse_dns {
        output.push_str(&format!("Reverse DNS: {}\n", rdns));
    }

    output.push_str("\n--- Flags ---\n");
    if let Some(true) = intel.is_tor_exit {
        output.push_str("⚠ TOR Exit Node\n");
    }
    if let Some(true) = intel.is_vpn {
        output.push_str("⚠ VPN\n");
    }
    if let Some(true) = intel.is_proxy {
        output.push_str("⚠ Proxy\n");
    }
    if let Some(true) = intel.is_hosting {
        output.push_str("⚠ Hosting/Datacenter\n");
    }
    if let Some(score) = intel.threat_score {
        output.push_str(&format!("Threat Score: {}%\n", score));
    }

    if let Some(ref org) = intel.whois_org {
        output.push_str("\n--- WHOIS ---\n");
        output.push_str(&format!("Organization: {}\n", org));
    }
    if let Some(ref registrar) = intel.whois_registrar {
        output.push_str(&format!("Registrar: {}\n", registrar));
    }
    if let Some(ref abuse) = intel.whois_abuse_contact {
        output.push_str(&format!("Abuse Contact: {}\n", abuse));
    }

    if let Some(ref ports) = intel.open_ports {
        if !ports.is_empty() {
            output.push_str("\n--- Shodan ---\n");
            output.push_str(&format!(
                "Open Ports: {}\n",
                ports
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    if let Some(ref hostnames) = intel.hostnames {
        if !hostnames.is_empty() {
            output.push_str(&format!("Hostnames: {}\n", hostnames.join(", ")));
        }
    }
    if let Some(ref tags) = intel.shodan_tags {
        if !tags.is_empty() {
            output.push_str(&format!("Tags: {}\n", tags.join(", ")));
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intel_new() {
        let intel = AttackerIntel::new("8.8.8.8".to_string());
        assert_eq!(intel.ip, "8.8.8.8");
        assert!(intel.gathered_at.is_some());
    }
}
