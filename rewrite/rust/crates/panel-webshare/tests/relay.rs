use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use xcli_panel_webshare::probe::ProbeError;
use xcli_panel_webshare::region::{maintain, Maintenance, RegionError, Session as RegionSession};
use xcli_panel_webshare::relay::{handle_fixture, InvalidPool, Pool, Session};

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}
fn session(name: &str) -> Session {
    Session::new(name.to_owned(), now() + 1800, now())
}
async fn listener() -> TcpListener {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap()
}
async fn pair(pool: Pool, endpoint: SocketAddr) -> (TcpStream, tokio::task::JoinHandle<()>) {
    let server = listener().await;
    let address = server.local_addr().unwrap();
    let client = TcpStream::connect(address).await.unwrap();
    let (accepted, _) = server.accept().await.unwrap();
    (
        client,
        tokio::spawn(handle_fixture(accepted, pool, endpoint)),
    )
}
async fn greet(client: &mut TcpStream) {
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut answer = [0u8; 2];
    client.read_exact(&mut answer).await.unwrap();
    assert_eq!(answer, [5, 0]);
}
async fn connect_domain(client: &mut TcpStream) {
    let mut request = vec![5, 1, 0, 3, 11];
    request.extend_from_slice(b"example.com");
    request.extend_from_slice(&443u16.to_be_bytes());
    client.write_all(&request).await.unwrap();
    let mut answer = [0u8; 10];
    client.read_exact(&mut answer).await.unwrap();
    assert_eq!(answer, [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
}
async fn provider(mut stream: TcpStream, attempts: Arc<Mutex<Vec<String>>>) {
    let mut greeting = [0u8; 3];
    if stream.read_exact(&mut greeting).await.is_err() {
        return;
    }
    assert_eq!(greeting, [5, 1, 2]);
    stream.write_all(&[5, 2]).await.unwrap();
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await.unwrap();
    assert_eq!(header[0], 1);
    let mut name = vec![0u8; header[1] as usize];
    stream.read_exact(&mut name).await.unwrap();
    let length = stream.read_u8().await.unwrap();
    let mut password = vec![0u8; length as usize];
    stream.read_exact(&mut password).await.unwrap();
    assert_eq!(password, b"synthetic-password");
    let name = String::from_utf8(name).unwrap();
    attempts.lock().unwrap().push(name.clone());
    if name == "bad-session" {
        stream.write_all(&[1, 1]).await.unwrap();
        return;
    }
    stream.write_all(&[1, 0]).await.unwrap();
    let mut request = [0u8; 4];
    stream.read_exact(&mut request).await.unwrap();
    assert_eq!(request, [5, 1, 0, 3]);
    let length = stream.read_u8().await.unwrap();
    let mut domain = vec![0u8; length as usize];
    stream.read_exact(&mut domain).await.unwrap();
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await.unwrap();
    assert_eq!(domain, b"example.com");
    assert_eq!(port, 443u16.to_be_bytes());
    stream
        .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut buffer = [0u8; 128];
    loop {
        match stream.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if stream.write_all(&buffer[..n]).await.is_err() {
                    break;
                }
            }
        }
    }
}

#[tokio::test]
async fn failed_upstream_is_promoted_before_payload_and_revocation_closes_stream() {
    let upstream = listener().await;
    let endpoint = upstream.local_addr().unwrap();
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let seen = attempts.clone();
    let fake = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = upstream.accept().await else {
                break;
            };
            tokio::spawn(provider(stream, seen.clone()));
        }
    });
    let pool = Pool::new(Arc::new(Semaphore::new(128)));
    pool.replace(
        true,
        "synthetic-password".into(),
        vec![session("bad-session"), session("good-session")],
    )
    .unwrap();
    let epoch = pool.generation().unwrap();
    let stamp = now();
    let mut old = RegionSession::new("bad-session".into(), stamp + 1800).unwrap();
    old.exit_ip = Some("8.8.8.1".parse().unwrap());
    old.exit_country = "US".into();
    old.last_success = stamp;
    old.last_checked = stamp;
    let mut backup = RegionSession::new("good-session".into(), stamp + 1800).unwrap();
    backup.exit_ip = Some("8.8.8.2".parse().unwrap());
    backup.exit_country = "US".into();
    backup.last_success = stamp;
    backup.last_checked = stamp;
    let prior = vec![old, backup];
    let pending = maintain(
        Maintenance {
            epoch,
            country: "US",
            before: &prior,
            now: stamp,
            last_used: stamp,
            cooldown: stamp + 3600,
            forced: false,
        },
        |_| Err(ProbeError::Unavailable),
        || Err(RegionError::InvalidInput),
    )
    .unwrap();
    let (mut client, relay) = pair(pool.clone(), endpoint).await;
    greet(&mut client).await;
    connect_domain(&mut client).await;
    client.write_all(b"first-payload").await.unwrap();
    let mut echoed = [0u8; 13];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"first-payload");
    assert_eq!(&*attempts.lock().unwrap(), &["bad-session", "good-session"]);
    assert_eq!(pool.failovers(), 1);
    pool.commit_sessions(epoch, |current| {
        let outcome = pending.finish(epoch, true, current).ok_or(InvalidPool)?;
        Ok((
            outcome
                .sessions
                .iter()
                .map(RegionSession::relay_session)
                .collect(),
            (),
        ))
    })
    .unwrap();
    let (mut second, relay2) = pair(pool.clone(), endpoint).await;
    greet(&mut second).await;
    connect_domain(&mut second).await;
    assert_eq!(
        &*attempts.lock().unwrap(),
        &["bad-session", "good-session", "good-session"]
    );
    pool.replace(false, String::new(), vec![]).unwrap();
    let mut one = [0u8; 1];
    assert_eq!(
        timeout(Duration::from_secs(2), client.read(&mut one))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert_eq!(
        timeout(Duration::from_secs(2), second.read(&mut one))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    timeout(Duration::from_secs(2), relay)
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(2), relay2)
        .await
        .unwrap()
        .unwrap();
    fake.abort();
}

#[tokio::test]
async fn rejects_udp_private_addresses_and_unavailable_pools() {
    let upstream = listener().await;
    let endpoint = upstream.local_addr().unwrap();
    let pool = Pool::new(Arc::new(Semaphore::new(128)));
    pool.replace(
        true,
        "synthetic-password".into(),
        vec![session("good-session")],
    )
    .unwrap();
    for (request, code) in [
        (vec![5, 3, 0, 1, 8, 8, 8, 8, 0, 53], 7),
        (vec![5, 1, 0, 1, 127, 0, 0, 1, 1, 187], 1),
        (
            vec![
                5, 1, 0, 3, 9, b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's', b't', 1, 187,
            ],
            1,
        ),
    ] {
        let (mut client, task) = pair(pool.clone(), endpoint).await;
        greet(&mut client).await;
        client.write_all(&request).await.unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], code);
        task.await.unwrap();
    }
    assert!(timeout(Duration::from_millis(100), upstream.accept())
        .await
        .is_err());
    pool.replace(false, String::new(), vec![]).unwrap();
    let (mut client, task) = pair(pool, endpoint).await;
    greet(&mut client).await;
    let mut request = vec![5, 1, 0, 3, 11];
    request.extend_from_slice(b"example.com");
    request.extend_from_slice(&443u16.to_be_bytes());
    client.write_all(&request).await.unwrap();
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 1);
    task.await.unwrap();
}

#[tokio::test]
async fn respects_shared_connection_limit() {
    let upstream = listener().await;
    let endpoint = upstream.local_addr().unwrap();
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let fake = tokio::spawn(async move {
        let (stream, _) = upstream.accept().await.unwrap();
        provider(stream, attempts).await;
    });
    let pool = Pool::new(Arc::new(Semaphore::new(1)));
    pool.replace(
        true,
        "synthetic-password".into(),
        vec![session("good-session")],
    )
    .unwrap();
    let (mut first, task) = pair(pool.clone(), endpoint).await;
    greet(&mut first).await;
    connect_domain(&mut first).await;
    let (mut second, task2) = pair(pool, endpoint).await;
    let mut answer = [0u8; 1];
    assert_eq!(
        timeout(Duration::from_secs(1), second.read(&mut answer))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    task2.await.unwrap();
    drop(first);
    task.await.unwrap();
    fake.await.unwrap();
}

#[tokio::test]
async fn disabling_during_upstream_handshake_prevents_acceptance() {
    let server = listener().await;
    let endpoint = server.local_addr().unwrap();
    let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let fake = tokio::spawn(async move {
        let (mut upstream, _) = server.accept().await.unwrap();
        let mut greeting = [0u8; 3];
        upstream.read_exact(&mut greeting).await.unwrap();
        upstream.write_all(&[5, 2]).await.unwrap();
        let mut header = [0u8; 2];
        upstream.read_exact(&mut header).await.unwrap();
        let mut user = vec![0; header[1] as usize];
        upstream.read_exact(&mut user).await.unwrap();
        let size = upstream.read_u8().await.unwrap();
        let mut password = vec![0; size as usize];
        upstream.read_exact(&mut password).await.unwrap();
        seen_tx.send(()).unwrap();
        release_rx.await.unwrap();
        if upstream.write_all(&[1, 0]).await.is_err() {
            return;
        }
        let mut request = [0u8; 4];
        if upstream.read_exact(&mut request).await.is_err() {
            return;
        }
        let size = upstream.read_u8().await.unwrap();
        let mut destination = vec![0; size as usize + 2];
        upstream.read_exact(&mut destination).await.unwrap();
        let _ = upstream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await;
    });
    let pool = Pool::new(Arc::new(Semaphore::new(1)));
    pool.replace(
        true,
        "synthetic-password".into(),
        vec![session("good-session")],
    )
    .unwrap();
    let (mut client, relay) = pair(pool.clone(), endpoint).await;
    greet(&mut client).await;
    let mut request = vec![5, 1, 0, 3, 11];
    request.extend_from_slice(b"example.com");
    request.extend_from_slice(&443u16.to_be_bytes());
    client.write_all(&request).await.unwrap();
    seen_rx.await.unwrap();
    pool.replace(false, String::new(), vec![]).unwrap();
    release_tx.send(()).unwrap();
    let mut reply = [0u8; 10];
    timeout(Duration::from_secs(2), client.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply[1], 1);
    timeout(Duration::from_secs(2), relay)
        .await
        .unwrap()
        .unwrap();
    fake.await.unwrap();
}
