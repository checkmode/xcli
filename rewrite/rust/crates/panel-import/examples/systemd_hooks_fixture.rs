//! Exercises the service switch only with disposable commands under /var/lib.
#[cfg(target_os = "linux")]
fn main() {
    use std::path::{Path, PathBuf};
    use std::time::Duration;
    use xcli_panel_import::journal::Hooks;
    use xcli_panel_import::systemd::{Options, ServiceHooks};
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_default();
    let root = PathBuf::from(args.next().unwrap_or_default());
    let uid = args.next().and_then(|v| v.parse().ok()).unwrap_or(0);
    let gid = args.next().and_then(|v| v.parse().ok()).unwrap_or(0);
    let port = args.next().and_then(|v| v.parse().ok()).unwrap_or(0);
    if unsafe { libc::geteuid() } != 0
        || !["switch", "stop"].contains(&mode.as_str())
        || root.parent() != Some(Path::new("/var/lib"))
        || !root
            .file_name()
            .and_then(|v| v.to_str())
            .is_some_and(|v| v.starts_with("xcli-switch-fixture-"))
        || std::fs::canonicalize(&root).ok().as_deref() != Some(root.as_path())
        || args.next().is_some()
    {
        std::process::exit(2);
    }
    let options = Options {
        systemctl: root.join("systemctl"),
        nginx: root.join("nginx"),
        checkpoint: root.join("checkpoint"),
        database: root.join("database"),
        core_binary: root.join("xray"),
        core_pid_file: root.join("pid"),
        core_api: "127.0.0.1:10085".into(),
        panel_uid: uid,
        panel_gid: gid,
        panel_port: port,
        settings: root.join("settings.json"),
        monitor_report: root.join("monitor/report.json"),
        core_unit: "xcli-core.service".into(),
        panel_unit: "xcli-panel.service".into(),
        monitor_unit: "xcli-monitor.service".into(),
        health_timeout: Duration::from_secs(5),
    };
    let result = ServiceHooks::new(options).and_then(|mut hooks| {
        hooks.stop()?;
        if mode == "switch" {
            hooks.start_and_check()?;
        }
        Ok(())
    });
    if result.is_err() {
        std::process::exit(1);
    }
}
#[cfg(not(target_os = "linux"))]
fn main() {
    std::process::exit(2);
}
