//! DNS-over-UDP check through one authenticated loopback SOCKS listener.
use crate::{Invalid, SocksAuth};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// Probe a fixed public resolver. Only a loopback SOCKS UDP relay is accepted.
pub fn dns(local_port: u16, auth: &SocksAuth) -> Result<u64, Invalid> {
    dns_inner(local_port, auth, Ipv4Addr::new(1, 1, 1, 1), 53)
}
fn dns_inner(
    local_port: u16,
    auth: &SocksAuth,
    target: Ipv4Addr,
    target_port: u16,
) -> Result<u64, Invalid> {
    if local_port == 0 {
        return Err(Invalid);
    }
    let started = Instant::now();
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, local_port));
    let mut control =
        TcpStream::connect_timeout(&address, Duration::from_secs(6)).map_err(|_| Invalid)?;
    control
        .set_read_timeout(Some(Duration::from_secs(6)))
        .map_err(|_| Invalid)?;
    control
        .set_write_timeout(Some(Duration::from_secs(6)))
        .map_err(|_| Invalid)?;
    control.write_all(&[5, 1, 2]).map_err(|_| Invalid)?;
    let mut method = [0u8; 2];
    control.read_exact(&mut method).map_err(|_| Invalid)?;
    if method != [5, 2] {
        return Err(Invalid);
    }
    let user = auth.username.as_bytes();
    let password = auth.password.as_bytes();
    if user.is_empty() || user.len() > 255 || password.is_empty() || password.len() > 255 {
        return Err(Invalid);
    }
    let mut credentials = Zeroizing::new(Vec::with_capacity(user.len() + password.len() + 3));
    credentials.extend_from_slice(&[1, user.len() as u8]);
    credentials.extend_from_slice(user);
    credentials.push(password.len() as u8);
    credentials.extend_from_slice(password);
    control.write_all(&credentials).map_err(|_| Invalid)?;
    let mut reply = [0u8; 2];
    control.read_exact(&mut reply).map_err(|_| Invalid)?;
    if reply != [1, 0] {
        return Err(Invalid);
    }
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .map_err(|_| Invalid)?;
    let mut relay = [0u8; 10];
    control.read_exact(&mut relay).map_err(|_| Invalid)?;
    if relay[..4] != [5, 0, 0, 1] {
        return Err(Invalid);
    }
    let host = Ipv4Addr::new(relay[4], relay[5], relay[6], relay[7]);
    if host != Ipv4Addr::LOCALHOST && host != Ipv4Addr::UNSPECIFIED {
        return Err(Invalid);
    }
    let relay_port = u16::from_be_bytes([relay[8], relay[9]]);
    if relay_port == 0 {
        return Err(Invalid);
    }
    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|_| Invalid)?;
    udp.set_read_timeout(Some(Duration::from_secs(6)))
        .map_err(|_| Invalid)?;
    udp.set_write_timeout(Some(Duration::from_secs(6)))
        .map_err(|_| Invalid)?;
    udp.connect((Ipv4Addr::LOCALHOST, relay_port))
        .map_err(|_| Invalid)?;
    let mut id = [0u8; 2];
    getrandom::fill(&mut id).map_err(|_| Invalid)?;
    let octets = target.octets();
    let target_port = target_port.to_be_bytes();
    let header = [
        0,
        0,
        0,
        1,
        octets[0],
        octets[1],
        octets[2],
        octets[3],
        target_port[0],
        target_port[1],
    ];
    let mut packet = header.to_vec();
    packet.extend_from_slice(&[id[0], id[1], 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    packet.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
    if udp.send(&packet).map_err(|_| Invalid)? != packet.len() {
        return Err(Invalid);
    }
    let mut response = [0u8; 4096];
    let length = udp.recv(&mut response).map_err(|_| Invalid)?;
    if length < 22 || response[..10] != header || !crate::dns::valid(&response[10..length], id) {
        return Err(Invalid);
    }
    Ok(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    fn fixture(unsafe_relay: bool, wrong_id: bool) -> (u16, thread::JoinHandle<()>) {
        let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = server.local_addr().unwrap().port();
        let thread = thread::spawn(move || {
            let (mut stream, _) = server.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut hello = [0u8; 3];
            stream.read_exact(&mut hello).unwrap();
            assert_eq!(hello, [5, 1, 2]);
            stream.write_all(&[5, 2]).unwrap();
            let mut head = [0u8; 2];
            stream.read_exact(&mut head).unwrap();
            assert_eq!(head[0], 1);
            let mut user = vec![0; head[1] as usize];
            stream.read_exact(&mut user).unwrap();
            let mut len = [0];
            stream.read_exact(&mut len).unwrap();
            let mut pass = vec![0; len[0] as usize];
            stream.read_exact(&mut pass).unwrap();
            assert_eq!(user, b"fixture-user");
            assert_eq!(pass, b"synthetic-password");
            stream.write_all(&[1, 0]).unwrap();
            let mut request = [0; 10];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(request, [5, 3, 0, 1, 0, 0, 0, 0, 0, 0]);
            let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let relay = socket.local_addr().unwrap().port().to_be_bytes();
            let host = if unsafe_relay {
                [8, 8, 8, 8]
            } else {
                [127, 0, 0, 1]
            };
            stream
                .write_all(&[
                    5, 0, 0, 1, host[0], host[1], host[2], host[3], relay[0], relay[1],
                ])
                .unwrap();
            if unsafe_relay {
                return;
            }
            let mut incoming = [0u8; 512];
            let (length, peer) = socket.recv_from(&mut incoming).unwrap();
            assert!(length > 22);
            assert_eq!(&incoming[..10], &[0, 0, 0, 1, 1, 1, 1, 1, 0, 53]);
            let mut response = vec![
                0,
                0,
                0,
                1,
                1,
                1,
                1,
                1,
                0,
                53,
                incoming[10],
                incoming[11],
                0x81,
                0x80,
                0,
                1,
                0,
                1,
                0,
                0,
                0,
                0,
            ];
            response.extend_from_slice(&incoming[22..length]);
            response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 1, 1, 1]);
            if wrong_id {
                response[11] ^= 1;
            }
            socket.send_to(&response, peer).unwrap();
        });
        (port, thread)
    }
    #[test]
    fn authenticated_udp_probe_checks_response_and_rejects_nonloopback_relays() {
        let auth = SocksAuth {
            username: Zeroizing::new("fixture-user".into()),
            password: Zeroizing::new("synthetic-password".into()),
        };
        for (unsafe_relay, wrong_id, success) in [
            (false, false, true),
            (false, true, false),
            (true, false, false),
        ] {
            let (port, server) = fixture(unsafe_relay, wrong_id);
            assert_eq!(dns(port, &auth).is_ok(), success);
            server.join().unwrap();
        }
    }
    #[test]
    fn real_xray_authenticated_socks_transports_udp_dns_in_isolation() {
        use serde_json::json;
        use std::process::{Child, Command, Stdio};
        let Ok(xray) = std::env::var("XCLI_TEST_XRAY") else {
            return;
        };
        struct Process(Child);
        impl Drop for Process {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let resolver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        resolver
            .set_read_timeout(Some(Duration::from_secs(8)))
            .unwrap();
        let dns_port = resolver.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let mut query = [0u8; 512];
            let (length, peer) = resolver.recv_from(&mut query).unwrap();
            assert!(length >= 12);
            let mut response = vec![query[0], query[1], 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
            response.extend_from_slice(&query[12..length]);
            response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 1, 1, 1]);
            resolver.send_to(&response, peer).unwrap();
        });
        let socket = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let socks_port = socket.local_addr().unwrap().port();
        drop(socket);
        let auth = SocksAuth::random().unwrap();
        let config = crate::Sensitive(
            json!({"log":{"loglevel":"none"},"inbounds":[{"listen":"127.0.0.1","port":socks_port,
            "protocol":"socks","settings":{"auth":"password","udp":true,
            "accounts":[{"user":auth.username.as_str(),"pass":auth.password.as_str()}]}}],
            "outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.1/32"]}]}}]}),
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
        while TcpStream::connect((Ipv4Addr::LOCALHOST, socks_port)).is_err() {
            assert!(process.0.try_wait().unwrap().is_none());
            assert!(
                Instant::now() < deadline,
                "disposable Xray SOCKS listener did not start"
            );
            thread::sleep(Duration::from_millis(20));
        }
        let wrong = SocksAuth {
            username: Zeroizing::new("wrong".into()),
            password: Zeroizing::new("synthetic".into()),
        };
        assert!(dns_inner(socks_port, &wrong, Ipv4Addr::LOCALHOST, dns_port).is_err());
        assert!(dns_inner(socks_port, &auth, Ipv4Addr::LOCALHOST, dns_port).is_ok());
        server.join().unwrap();
    }
}
