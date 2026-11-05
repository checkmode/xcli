use std::collections::BTreeSet;
use std::net::TcpListener;
use std::path::Path;
use std::time::{Duration, Instant};
use xcli_panel_controller::{Core, Error};
use xcli_panel_xray::ManagedCore;

#[test]
fn management_address_and_tag_are_restricted() {
    for api in [
        "0.0.0.0:1234",
        "127.0.0.2:1234",
        "192.0.2.1:1234",
        "localhost:1234",
        "127.0.0.1:0",
    ] {
        assert!(matches!(
            ManagedCore::new(
                api,
                Path::new("/bin/sleep"),
                Path::new("/tmp/xcli-test-pid"),
                BTreeSet::new()
            ),
            Err(Error::InvalidState)
        ));
    }
    assert!(matches!(
        ManagedCore::new(
            "127.0.0.1:1",
            Path::new("/bin/sleep"),
            Path::new("/tmp/xcli-test-pid"),
            BTreeSet::from(["residential-XX-hy2".into()])
        ),
        Err(Error::InvalidState)
    ));
    let mut core = ManagedCore::new(
        "127.0.0.1:1",
        Path::new("/bin/sleep"),
        Path::new("/tmp/xcli-test-pid"),
        BTreeSet::new(),
    )
    .unwrap();
    assert!(matches!(core.users("arbitrary"), Err(Error::InvalidState)));
}

#[test]
fn stalled_grpc_endpoint_times_out() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = std::thread::spawn(move || {
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            match listener.accept() {
                Ok((socket, _)) => {
                    std::thread::sleep(Duration::from_secs(5));
                    drop(socket);
                    break;
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < until =>
                {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(_) => break,
            }
        }
    });
    let mut core = ManagedCore::new(
        &address.to_string(),
        Path::new("/bin/sleep"),
        Path::new("/tmp/xcli-test-pid"),
        BTreeSet::new(),
    )
    .unwrap();
    let start = Instant::now();
    assert!(matches!(core.counters(), Err(Error::CoreUnavailable)));
    assert!(start.elapsed() < Duration::from_millis(4500));
    drop(core);
    server.join().unwrap();
}
