//! Experimental fixed-proxy input validation. This is not the privileged
//! import worker and does not probe, write configuration, or apply changes.
use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use zeroize::Zeroizing;

#[cfg(target_os = "linux")]
mod batch;
pub mod config;
#[cfg(target_os = "linux")]
pub mod coordinator;
pub mod journal;
#[cfg(target_os = "linux")]
pub mod launcher;
#[cfg(target_os = "linux")]
pub mod preview;
pub mod probe;
pub mod publisher;
pub mod queue;
pub mod report;
pub mod request;
#[cfg(target_os = "linux")]
pub mod runner;
#[cfg(target_os = "linux")]
pub mod systemd;
#[cfg(target_os = "linux")]
pub mod validate;
pub mod vmess;
pub mod vmess_probe;

pub struct Proxy {
    pub address: Ipv4Addr,
    pub port: u16,
    username: Zeroizing<String>,
    password: Zeroizing<String>,
}
impl Proxy {
    pub fn username(&self) -> &str {
        &self.username
    }
    pub fn password(&self) -> &str {
        &self.password
    }
}
#[derive(Debug, PartialEq, Eq)]
pub struct ImportError(pub &'static str);

/// The same conservative IPv4 boundary as the legacy panel. The privileged
/// worker must independently revalidate any address before making a request.
pub fn public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || a >= 224
        || a == 100 && (64..=127).contains(&b)
        || a == 169 && b == 254
        || a == 172 && (16..=31).contains(&b)
        || a == 192 && (b == 168 || b == 0 && (c == 0 || c == 2) || b == 88 && c == 99)
        || a == 198 && (b == 18 || b == 19 || b == 51 && c == 100)
        || a == 203 && b == 0 && c == 113)
}
fn credential(value: &str) -> bool {
    !value.is_empty() && value.len() <= 255 && !value.chars().any(|c| c < ' ' || c == '\u{7f}')
}
pub fn parse_fixed(text: &str) -> Result<Vec<Proxy>, ImportError> {
    if text.is_empty() || text.chars().count() > 12_000 {
        return Err(ImportError("字段长度不符合要求"));
    }
    let mut result = Vec::new();
    let mut peers = BTreeSet::new();
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.bytes().all(|b| b == b' ' || b == b'\t') {
            continue;
        }
        if result.len() >= 20 {
            return Err(ImportError("每次最多导入 20 个代理"));
        }
        let mut fields = line.splitn(4, ':');
        let address = fields
            .next()
            .ok_or(ImportError("每行格式应为 HOST:PORT:USER:PASS"))?;
        let port = fields
            .next()
            .ok_or(ImportError("每行格式应为 HOST:PORT:USER:PASS"))?;
        let username = fields
            .next()
            .ok_or(ImportError("每行格式应为 HOST:PORT:USER:PASS"))?;
        let password = fields
            .next()
            .ok_or(ImportError("每行格式应为 HOST:PORT:USER:PASS"))?;
        let ip = address
            .parse::<Ipv4Addr>()
            .ok()
            .filter(|ip| ip.to_string() == address && public_ipv4(*ip))
            .ok_or(ImportError("仅支持公网 IPv4 地址"))?;
        if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ImportError("代理端口不正确"));
        }
        let port = port
            .parse::<u16>()
            .ok()
            .filter(|value| *value != 0)
            .ok_or(ImportError("代理端口不正确"))?;
        if !credential(username) || !credential(password) {
            return Err(ImportError("账号或密码格式不正确"));
        }
        if !peers.insert((ip, port)) {
            return Err(ImportError("列表包含重复地址和端口"));
        }
        result.push(Proxy {
            address: ip,
            port,
            username: Zeroizing::new(username.to_owned()),
            password: Zeroizing::new(password.to_owned()),
        });
    }
    if result.is_empty() {
        return Err(ImportError("请填写至少一个代理"));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_multiple_public_proxies_and_preserves_password_colons() {
        let values =
            parse_fixed("1.1.1.1:0080:user:pass:extra\r\n\n8.8.8.8:443:alice:secret").unwrap();
        assert_eq!(values.len(), 2);
        assert_eq!(values[0].port, 80);
        assert_eq!(values[0].username(), "user");
        assert_eq!(values[0].password(), "pass:extra");
    }
    #[test]
    fn rejects_private_invalid_duplicate_and_injected_values() {
        for text in [
            "127.0.0.1:80:u:p",
            "100.64.0.1:80:u:p",
            "192.0.2.1:80:u:p",
            "1.1.1.01:80:u:p",
            "example.com:80:u:p",
            "224.0.0.1:80:u:p",
            "1.1.1.1:0:u:p",
            "1.1.1.1:65536:u:p",
            "1.1.1.1:80:u:\u{7f}",
            "1.1.1.1:80:u:p\n1.1.1.1:00080:x:y",
            "\n \t\r\n",
        ] {
            assert!(parse_fixed(text).is_err(), "invalid fixture was accepted");
        }
        let rows = (1..=21)
            .map(|port| format!("1.1.1.1:{port}:u:p\n"))
            .collect::<String>();
        assert!(parse_fixed(&rows).is_err());
    }
}
