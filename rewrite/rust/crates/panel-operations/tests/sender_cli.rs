use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn isolated_sender_rejects_private_destination_without_echoing_secrets() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let mut child = Command::new(env!("CARGO_BIN_EXE_xcli-webhook-sender"))
        .arg("--experimental")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let input=br#"{"url":"https://127.0.0.1/private-synthetic","bearer":"synthetic-bearer","signing":"synthetic-signing","payload":{"id":"fixture-id"},"timestamp":123}"#;
    child.stdin.take().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["status"], 0);
    assert_eq!(result["error"], true);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("synthetic"));
    assert!(output.stderr.is_empty());
}
