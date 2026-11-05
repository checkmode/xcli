//! An isolated, non-root Xray child for verifying one pinned VMess outbound.
//! Production privilege confinement and installation are not yet implemented.
use crate::probe::{run, ProbeError, ProbeResult, Targets};
use crate::vmess::{resolve_public, SecretJson, VmessProxy};
use crate::Proxy;
use serde_json::json;
use std::io::Write;
use std::net::{Ipv4Addr, TcpListener, TcpStream};
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

static PROBE_LIMIT: OnceLock<Arc<Semaphore>> = OnceLock::new();
pub struct VmessProbeResult {
    /// The exact verified server address must be used in the applied outbound.
    pub server_ip: Ipv4Addr,
    pub observed: ProbeResult,
}
struct Tunnel(Child);
impl Drop for Tunnel {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn random_hex(bytes: usize) -> Result<Zeroizing<String>, ProbeError> {
    let mut data = Zeroizing::new(vec![0u8; bytes]);
    getrandom::fill(&mut data).map_err(|_| ProbeError::Unavailable)?;
    Ok(Zeroizing::new(hex::encode(&*data)))
}
fn start(binary: &Path, outbound: &SecretJson) -> Result<(Tunnel, Proxy), ProbeError> {
    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|_| ProbeError::Unavailable)?;
    let port = listener
        .local_addr()
        .map_err(|_| ProbeError::Unavailable)?
        .port();
    drop(listener);
    let username = random_hex(12)?;
    let password = random_hex(24)?;
    let config = SecretJson::new(
        json!({"log":{"loglevel":"none"},"inbounds":[{"listen":"127.0.0.1","port":port,
        "protocol":"socks","settings":{"auth":"password","accounts":[{"user":username.as_str(),"pass":password.as_str()}]}}],
        "outbounds":[outbound.as_value()]}),
    );
    let data =
        Zeroizing::new(serde_json::to_vec(config.as_value()).map_err(|_| ProbeError::Unavailable)?);
    let mut command = Command::new(binary);
    command
        .args(["run", "-config", "stdin:"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/nonexistent");
    #[cfg(target_os = "linux")]
    {
        // SAFETY: prctl and getppid are async-signal-safe here; no allocation
        // or inherited locks are touched between fork and exec.
        let parent = unsafe { libc::getpid() };
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                    || libc::getppid() != parent
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let mut child = Tunnel(command.spawn().map_err(|_| ProbeError::Unavailable)?);
    child
        .0
        .stdin
        .take()
        .ok_or(ProbeError::Unavailable)?
        .write_all(&data)
        .map_err(|_| ProbeError::Unavailable)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child
            .0
            .try_wait()
            .map_err(|_| ProbeError::Unavailable)?
            .is_some()
        {
            return Err(ProbeError::Unavailable);
        }
        if TcpStream::connect_timeout(
            &(Ipv4Addr::LOCALHOST, port).into(),
            Duration::from_millis(200),
        )
        .is_ok()
        {
            break;
        }
        if Instant::now() >= deadline {
            return Err(ProbeError::Unavailable);
        }
        std::thread::sleep(Duration::from_millis(40));
    }
    Ok((
        child,
        Proxy {
            address: Ipv4Addr::LOCALHOST,
            port,
            username,
            password,
        },
    ))
}
fn verify(
    binary: &Path,
    outbound: &SecretJson,
    mut targets: Targets,
) -> Result<ProbeResult, ProbeError> {
    let (_tunnel, proxy) = start(binary, outbound)?;
    targets.proxy = format!("socks5h://127.0.0.1:{}", proxy.port);
    run(&proxy, &targets)
}
/// Must run as a non-root, sandboxed probe account. The fixed Xray binary,
/// outbound IP and HTTPS targets cannot be supplied by the request.
pub async fn probe_vmess(proxy: &VmessProxy) -> Result<VmessProbeResult, ProbeError> {
    // SAFETY: geteuid has no preconditions and reads only process identity.
    if unsafe { libc::geteuid() } == 0 {
        return Err(ProbeError::Unavailable);
    }
    let ip = resolve_public(proxy)
        .await
        .map_err(|_| ProbeError::InvalidExit)?;
    let outbound = proxy.outbound(ip).map_err(|_| ProbeError::InvalidExit)?;
    let limit = PROBE_LIMIT
        .get_or_init(|| Arc::new(Semaphore::new(4)))
        .clone();
    let permit = tokio::time::timeout(Duration::from_secs(8), limit.acquire_owned())
        .await
        .map_err(|_| ProbeError::Unavailable)?
        .map_err(|_| ProbeError::Unavailable)?;
    let task = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        verify(
            Path::new("/usr/local/lib/xcli/xray"),
            &outbound,
            Targets {
                proxy: String::new(),
                trace: "https://www.cloudflare.com/cdn-cgi/trace".into(),
                dns: "https://1.1.1.1/dns-query".into(),
                root: None,
            },
        )
    });
    let observed = tokio::time::timeout(Duration::from_secs(55), task)
        .await
        .map_err(|_| ProbeError::Unavailable)?
        .map_err(|_| ProbeError::Unavailable)??;
    Ok(VmessProbeResult {
        server_ip: ip,
        observed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vmess::parse_links;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use std::io::{BufRead, BufReader};

    struct Fixture(Child);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    fn endpoint(cert: &Path, key: &Path) -> (Fixture, u16) {
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proxy_tls.py");
        let mut child = Command::new("python3")
            .arg("-u")
            .arg(script)
            .arg(cert)
            .arg(key)
            .args(["socks", "good"])
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
        (Fixture(child), ports[1])
    }
    #[test]
    fn starts_an_authenticated_child_and_always_reaps_it() {
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
        let root = reqwest::Certificate::from_pem(&std::fs::read(&cert).unwrap()).unwrap();
        let (_server, port) = endpoint(&cert, &key);
        let link =
            json!({"add":"example.com","port":443,"id":"11111111-2222-3333-4444-555555555555"});
        let text = format!(
            "vmess://{}",
            STANDARD.encode(serde_json::to_vec(&link).unwrap())
        );
        let proxies = parse_links(&text).unwrap();
        let outbound = proxies[0].outbound("8.8.8.8".parse().unwrap()).unwrap();
        let fake = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake_xray.py");
        let targets = Targets {
            proxy: String::new(),
            trace: format!("https://localhost:{port}/trace"),
            dns: format!("https://localhost:{port}/dns-query"),
            root: Some(root),
        };
        let result = verify(&fake, &outbound, targets).unwrap();
        assert_eq!(result.exit_ip.to_string(), "8.8.8.8");
        assert_eq!(result.country, "US");
        let (child, _) = start(&fake, &outbound).unwrap();
        let pid = child.0.id();
        drop(child);
        // SAFETY: signal zero performs only an existence/permission check.
        assert_ne!(unsafe { libc::kill(pid as libc::pid_t, 0) }, 0);
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn child_lifetime_fixture() {
        if std::env::var_os("XCLI_TEST_IMPORT_PDEATH").is_none() {
            return;
        }
        let link =
            json!({"add":"example.com","port":443,"id":"11111111-2222-3333-4444-555555555555"});
        let text = format!(
            "vmess://{}",
            STANDARD.encode(serde_json::to_vec(&link).unwrap())
        );
        let proxies = parse_links(&text).unwrap();
        let outbound = proxies[0].outbound("8.8.8.8".parse().unwrap()).unwrap();
        let fake = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake_xray.py");
        let (child, _) = start(&fake, &outbound).unwrap();
        println!("XCLI_CHILD_PID={}", child.0.id());
        std::io::stdout().flush().unwrap();
        loop {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_child_stops_when_its_parent_is_killed() {
        let mut parent = Tunnel(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "vmess_probe::tests::child_lifetime_fixture",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("XCLI_TEST_IMPORT_PDEATH", "1")
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let output = parent.0.stdout.take().unwrap();
        let (sent, received) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(output).lines().map_while(Result::ok) {
                if let Some((_, value)) = line.split_once("XCLI_CHILD_PID=") {
                    let _ = sent.send(value.trim().parse::<u32>());
                    break;
                }
            }
        });
        let pid = received
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .unwrap();
        drop(parent);
        reader.join().unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"));
            if stat.as_ref().is_err()
                || stat
                    .as_ref()
                    .ok()
                    .and_then(|value| value.rsplit_once(") "))
                    .is_some_and(|(_, tail)| tail.starts_with('Z'))
            {
                break;
            }
            if Instant::now() >= deadline {
                // SAFETY: this PID belongs to the isolated child just started above.
                unsafe {
                    libc::kill(pid as libc::pid_t, libc::SIGKILL);
                }
                panic!("isolated child survived its parent");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    #[test]
    fn real_xray_vmess_tunnel_carries_https_and_dns_in_isolation() {
        let Some(binary) = std::env::var_os("XCLI_TEST_XRAY") else {
            return;
        };
        let binary = std::path::PathBuf::from(binary);
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("key.pem");
        let cert = dir.path().join("cert.pem");
        let openssl = dir.path().join("openssl.cnf");
        std::fs::write(&openssl,"[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\n").unwrap();
        assert!(Command::new("openssl")
            .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-config"])
            .arg(&openssl)
            .arg("-keyout")
            .arg(&key)
            .arg("-out")
            .arg(&cert)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success());
        let root = reqwest::Certificate::from_pem(&std::fs::read(&cert).unwrap()).unwrap();
        let (_endpoint, web_port) = endpoint(&cert, &key);
        let uuid = "11111111-2222-3333-4444-555555555555";
        for network in ["tcp", "ws", "grpc"] {
            for use_tls in [false, true] {
                let reserved = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
                let server_port = reserved.local_addr().unwrap().port();
                drop(reserved);
                let mut stream = match network {
                    "ws" => json!({"network":"ws","wsSettings":{"path":"/fixture"}}),
                    "grpc" => json!({"network":"grpc","grpcSettings":{"serviceName":"fixture"}}),
                    _ => json!({"network":"tcp"}),
                };
                if use_tls {
                    stream["security"] = json!("tls");
                    stream["tlsSettings"] =
                        json!({"certificates":[{"certificateFile":cert,"keyFile":key}]});
                }
                let config = SecretJson::new(
                    json!({"log":{"loglevel":"none"},"inbounds":[{"listen":"127.0.0.1","port":server_port,
            "protocol":"vmess","settings":{"clients":[{"id":uuid}]},"streamSettings":stream}],
            "outbounds":[{"protocol":"freedom","settings":{"domainStrategy":"UseIPv4",
                "finalRules":[{"action":"allow","ip":["127.0.0.1/32"]}]}}]}),
                );
                let mut server = Tunnel(
                    Command::new(&binary)
                        .args(["run", "-config", "stdin:"])
                        .stdin(Stdio::piped())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn()
                        .unwrap(),
                );
                server
                    .0
                    .stdin
                    .take()
                    .unwrap()
                    .write_all(&serde_json::to_vec(config.as_value()).unwrap())
                    .unwrap();
                let deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    assert!(
                        server.0.try_wait().unwrap().is_none(),
                        "synthetic Xray server stopped"
                    );
                    if TcpStream::connect_timeout(
                        &(Ipv4Addr::LOCALHOST, server_port).into(),
                        Duration::from_millis(100),
                    )
                    .is_ok()
                    {
                        break;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "synthetic Xray server did not listen"
                    );
                    std::thread::sleep(Duration::from_millis(20));
                }
                let mut link =
                    json!({"add":"example.com","port":server_port,"id":uuid,"net":network});
                if network == "ws" {
                    link["path"] = json!("/fixture");
                }
                if network == "grpc" {
                    link["serviceName"] = json!("fixture");
                }
                if use_tls {
                    link["tls"] = json!("tls");
                    link["sni"] = json!("localhost");
                }
                let text = format!(
                    "vmess://{}",
                    STANDARD.encode(serde_json::to_vec(&link).unwrap())
                );
                let proxies = parse_links(&text).unwrap();
                let normal = proxies[0].outbound("8.8.8.8".parse().unwrap()).unwrap();
                let mut synthetic = normal.as_value().clone();
                synthetic["settings"]["vnext"][0]["address"] = json!("127.0.0.1");
                if use_tls {
                    synthetic["streamSettings"]["tlsSettings"]["certificates"] =
                        json!([{"certificateFile":cert,"usage":"verify"}]);
                }
                if use_tls && network == "tcp" {
                    let mut wrong = synthetic.clone();
                    wrong["streamSettings"]["tlsSettings"]["serverName"] = json!("wrong.example");
                    let wrong = SecretJson::new(wrong);
                    let targets = Targets {
                        proxy: String::new(),
                        trace: format!("https://localhost:{web_port}/trace"),
                        dns: format!("https://localhost:{web_port}/dns-query"),
                        root: Some(root.clone()),
                    };
                    assert!(matches!(
                        verify(&binary, &wrong, targets),
                        Err(ProbeError::Unavailable)
                    ));
                }
                let synthetic = SecretJson::new(synthetic);
                let targets = Targets {
                    proxy: String::new(),
                    trace: format!("https://localhost:{web_port}/trace"),
                    dns: format!("https://localhost:{web_port}/dns-query"),
                    root: Some(root.clone()),
                };
                let result = verify(&binary, &synthetic, targets).unwrap_or_else(|_| {
                    panic!("synthetic VMess probe failed: {network}, TLS {use_tls}")
                });
                assert_eq!(result.exit_ip.to_string(), "8.8.8.8");
                assert_eq!(result.country, "US");
            }
        }
    }
}
