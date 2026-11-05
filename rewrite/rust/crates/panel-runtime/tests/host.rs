use std::fs;
use xcli_panel_runtime::{cpu_percent, sample};

#[test]
fn reads_realistic_counters_without_double_counting_guest_time() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("uptime"), "1234.5 600.0\n").unwrap();
    fs::write(root.path().join("loadavg"), "1.25 2.50 3.75 1/10 123\n").unwrap();
    fs::write(
        root.path().join("meminfo"),
        "MemTotal: 1000 kB\nMemAvailable: 250 kB\nSwapTotal: 500 kB\nSwapFree: 200 kB\n",
    )
    .unwrap();
    fs::write(
        root.path().join("stat"),
        "cpu 100 20 30 500 50 10 20 30 90 10\nbtime 1000\n",
    )
    .unwrap();
    let (host, ticks) = sample(root.path(), root.path());
    assert_eq!(ticks, Some((760, 550)));
    assert_eq!(host["uptime_seconds"], 1234.5);
    assert_eq!(host["memory"]["used"], 750 * 1024);
    assert_eq!(host["swap"]["used"], 300 * 1024);
    assert_eq!(host["load"][2], 3.75);
    assert_eq!(host["booted_at"], 1000);
    #[cfg(target_os = "linux")]
    assert!(host["disk"]["total"].as_u64().unwrap() > 0);
    assert_eq!(cpu_percent(Some((100, 70)), Some((200, 130))), Some(40.0));
    assert_eq!(cpu_percent(Some((100, 70)), Some((100, 70))), None);
    assert_eq!(cpu_percent(Some((100, 70)), Some((200, 180))), None);
}

#[test]
fn missing_invalid_oversized_and_fifo_sources_remain_unknown() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("uptime"), "NaN").unwrap();
    fs::write(root.path().join("loadavg"), "1 inf 3").unwrap();
    fs::write(
        root.path().join("meminfo"),
        format!("{}\n", "x".repeat(65537)),
    )
    .unwrap();
    fs::write(
        root.path().join("stat"),
        "cpu 18446744073709551615 10 3 4\n",
    )
    .unwrap();
    let (host, ticks) = sample(root.path(), &root.path().join("missing"));
    assert!(host["uptime_seconds"].is_null());
    assert!(host["load"].is_null());
    assert!(host["memory"].is_null());
    assert!(host["disk"].is_null());
    assert!(ticks.is_none());
    fs::remove_file(root.path().join("meminfo")).unwrap();
    let name = CString::new(root.path().join("meminfo").as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let start = std::time::Instant::now();
    assert!(sample(root.path(), root.path()).0["memory"].is_null());
    assert!(start.elapsed() < std::time::Duration::from_secs(1));
}
