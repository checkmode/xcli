//! Fixed HTTPS and encrypted-DNS probes through an authenticated local proxy.
use crate::report::{Dns, Https};
use crate::{Invalid, SocksAuth};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use reqwest::blocking::{Client, Response};
use reqwest::{redirect::Policy, Certificate, Proxy};
use std::io::Read;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

struct Targets {
    trace: String,
    dns: String,
    root: Option<Certificate>,
}
fn client(port: u16, auth: &SocksAuth, root: Option<&Certificate>) -> Result<Client, Invalid> {
    if port == 0 {
        return Err(Invalid);
    }
    let proxy = Proxy::all(format!("socks5h://127.0.0.1:{port}"))
        .map_err(|_| Invalid)?
        .basic_auth(&auth.username, &auth.password);
    let mut builder = Client::builder()
        .no_proxy()
        .proxy(proxy)
        .redirect(Policy::none())
        .https_only(true)
        .connect_timeout(Duration::from_secs(8))
        .timeout(Duration::from_secs(15));
    if let Some(cert) = root {
        builder = builder.add_root_certificate(cert.clone());
    }
    builder.build().map_err(|_| Invalid)
}
fn body(response: Response) -> Result<Zeroizing<Vec<u8>>, Invalid> {
    if !response.status().is_success() {
        return Err(Invalid);
    }
    let mut data = Zeroizing::new(Vec::new());
    response
        .take(8193)
        .read_to_end(&mut data)
        .map_err(|_| Invalid)?;
    if data.len() > 8192 {
        return Err(Invalid);
    }
    Ok(data)
}
fn trace(port: u16, auth: &SocksAuth, expected: Ipv4Addr, targets: &Targets) -> Https {
    let Ok(client) = client(port, auth, targets.root.as_ref()) else {
        return Https::Unavailable;
    };
    let started = Instant::now();
    let Ok(response) = client
        .get(&targets.trace)
        .send()
        .map_err(|_| Invalid)
        .and_then(body)
    else {
        return Https::ConnectionFailed;
    };
    let Ok(text) = std::str::from_utf8(&response) else {
        return Https::ConnectionFailed;
    };
    let observed = text.lines().rev().find_map(|line| line.strip_prefix("ip="));
    if observed != Some(expected.to_string().as_str()) {
        return Https::UnexpectedEgress;
    }
    Https::Ok(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX))
}
fn encrypted_dns(port: u16, auth: &SocksAuth, targets: &Targets) -> Dns {
    let Ok(client) = client(port, auth, targets.root.as_ref()) else {
        return Dns::Failed;
    };
    let mut id = [0u8; 2];
    if getrandom::fill(&mut id).is_err() {
        return Dns::Failed;
    }
    let mut packet = vec![id[0], id[1], 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    packet.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
    let started = Instant::now();
    let response = client
        .get(&targets.dns)
        .query(&[("dns", URL_SAFE_NO_PAD.encode(packet))])
        .header("accept", "application/dns-message")
        .send()
        .map_err(|_| Invalid)
        .and_then(body);
    let Ok(data) = response else {
        return Dns::Failed;
    };
    if !crate::dns::valid(&data, id) {
        return Dns::Failed;
    }
    Dns::Ok(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX))
}
/// These functions must run in a bounded blocking worker, not in an async task.
pub fn https(port: u16, auth: &SocksAuth, expected: Ipv4Addr) -> Https {
    trace(
        port,
        auth,
        expected,
        &Targets {
            trace: "https://www.cloudflare.com/cdn-cgi/trace".into(),
            dns: String::new(),
            root: None,
        },
    )
}
pub fn doh(port: u16, auth: &SocksAuth) -> Dns {
    encrypted_dns(
        port,
        auth,
        &Targets {
            trace: String::new(),
            dns: "https://1.1.1.1/dns-query".into(),
            root: None,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::path::Path;
    use std::process::{Child, Command, Stdio};
    struct Process(Child);
    impl Drop for Process {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    fn server(cert: &Path, key: &Path, mode: &str) -> (Process, u16, u16) {
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proxy_tls.py");
        let mut child = Command::new("python3")
            .args(["-u"])
            .arg(script)
            .arg(cert)
            .arg(key)
            .args(["socks", mode])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let ports: Vec<u16> = line
            .split_whitespace()
            .map(|value| value.parse().unwrap())
            .collect();
        (Process(child), ports[0], ports[1])
    }
    #[test]
    fn tls_and_doh_use_the_authenticated_proxy_and_reject_bad_responses() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("key.pem");
        let cert = dir.path().join("cert.pem");
        let config = dir.path().join("openssl.cnf");
        std::fs::write(&config,"[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\n").unwrap();
        let status = Command::new("openssl")
            .args([
                "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-config",
            ])
            .arg(&config)
            .arg("-keyout")
            .arg(&key)
            .arg("-out")
            .arg(&cert)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
        let root = Certificate::from_pem(&std::fs::read(&cert).unwrap()).unwrap();
        let auth = SocksAuth {
            username: Zeroizing::new("fixture-user".into()),
            password: Zeroizing::new("synthetic-password".into()),
        };
        let wrong = SocksAuth {
            username: Zeroizing::new("fixture-user".into()),
            password: Zeroizing::new("wrong".into()),
        };
        for mode in ["good", "dnsfail", "oversize"] {
            let (_server, port, web) = server(&cert, &key, mode);
            let targets = Targets {
                trace: format!("https://localhost:{web}/trace"),
                dns: format!("https://localhost:{web}/dns-query"),
                root: Some(root.clone()),
            };
            let expected = Ipv4Addr::new(8, 8, 8, 8);
            if mode == "oversize" {
                assert!(matches!(
                    trace(port, &auth, expected, &targets),
                    Https::ConnectionFailed
                ));
            } else {
                assert!(matches!(
                    trace(port, &auth, expected, &targets),
                    Https::Ok(_)
                ));
                assert!(matches!(
                    trace(port, &auth, Ipv4Addr::new(1, 1, 1, 1), &targets),
                    Https::UnexpectedEgress
                ));
            }
            if mode == "dnsfail" {
                assert!(matches!(encrypted_dns(port, &auth, &targets), Dns::Failed));
            } else {
                assert!(matches!(encrypted_dns(port, &auth, &targets), Dns::Ok(_)));
            }
            assert!(matches!(
                trace(port, &wrong, expected, &targets),
                Https::ConnectionFailed
            ));
            let untrusted = Targets {
                root: None,
                ..targets
            };
            assert!(matches!(
                trace(port, &auth, expected, &untrusted),
                Https::ConnectionFailed
            ));
        }
    }
    #[test]
    fn real_xray_socks_carries_tls_and_doh_in_isolation() {
        use serde_json::json;
        use std::io::Write;
        use std::net::{TcpListener, TcpStream};
        let Ok(xray) = std::env::var("XCLI_TEST_XRAY") else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("key.pem");
        let cert = dir.path().join("cert.pem");
        let status = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost",
                "-addext",
                "basicConstraints=critical,CA:FALSE",
            ])
            .arg("-keyout")
            .arg(&key)
            .arg("-out")
            .arg(&cert)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
        let root = Certificate::from_pem(&std::fs::read(&cert).unwrap()).unwrap();
        let (_server, _, web) = server(&cert, &key, "good");
        let socket = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = socket.local_addr().unwrap().port();
        drop(socket);
        let auth = SocksAuth::random().unwrap();
        let config = crate::Sensitive(
            json!({"log":{"loglevel":"none"},"inbounds":[{"listen":"127.0.0.1","port":port,
            "protocol":"socks","settings":{"auth":"password","udp":true,
            "accounts":[{"user":auth.username.as_str(),"pass":auth.password.as_str()}]}}],
            "outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.1/32"]}]},
            "streamSettings":{"sockopt":{"domainStrategy":"UseIPv4"}}}]}),
        );
        let config = Zeroizing::new(serde_json::to_vec(config.as_value()).unwrap());
        let mut process = Process(
            Command::new(xray)
                .args(["run", "-config", "stdin:"])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        process.0.stdin.take().unwrap().write_all(&config).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_err() {
            assert!(process.0.try_wait().unwrap().is_none());
            assert!(
                Instant::now() < deadline,
                "disposable Xray SOCKS listener did not start"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        let targets = Targets {
            trace: format!("https://localhost:{web}/trace"),
            dns: format!("https://localhost:{web}/dns-query"),
            root: Some(root),
        };
        assert!(matches!(
            trace(port, &auth, Ipv4Addr::new(8, 8, 8, 8), &targets),
            Https::Ok(_)
        ));
        assert!(matches!(encrypted_dns(port, &auth, &targets), Dns::Ok(_)));
    }
}
