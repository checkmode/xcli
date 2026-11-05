#![cfg(target_os = "linux")]
use std::process::{Command, Stdio};
use xcli_panel_controller::Error;
use xcli_panel_xray::ProcessIdentity;

#[test]
fn verifies_and_pins_only_the_expected_process_before_restart() {
    let dir = tempfile::tempdir().unwrap();
    let pid_file = dir.path().join("pids");
    let mut child = Command::new("/bin/sleep")
        .arg("60")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    struct Stop<'a>(&'a mut std::process::Child);
    impl Drop for Stop<'_> {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let process = Stop(&mut child);
    std::fs::write(&pid_file, format!("0\n{}\n", process.0.id())).unwrap();
    let wrong = ProcessIdentity::new(std::path::Path::new("/bin/ls"), &pid_file).unwrap();
    assert!(matches!(wrong.generation(), Err(Error::CoreUnavailable)));
    let identity = ProcessIdentity::new(std::path::Path::new("/bin/sleep"), &pid_file).unwrap();
    let generation = identity.generation().unwrap();
    assert!(matches!(identity.restart("1:1"), Err(Error::CoreChanged)));
    assert!(process.0.try_wait().unwrap().is_none());
    identity.restart(&generation).unwrap();
    assert!(!process.0.wait().unwrap().success());
    assert!(matches!(identity.generation(), Err(Error::CoreUnavailable)));
}
