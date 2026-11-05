#[cfg(target_os = "linux")]
mod linux {
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::Path;
    use std::time::{Duration, Instant};
    use xcli_panel_runtime::disk_probe::DiskProbe;

    #[test]
    fn isolated_real_probe_returns_the_requested_filesystem() {
        let root = tempfile::tempdir().unwrap();
        let source = Path::new(env!("CARGO_BIN_EXE_xcli-host-disk-probe"));
        let binary = root.path().join("disk-probe");
        std::fs::copy(source, &binary).unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut probe = DiskProbe::new(&binary, root.path()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let value = loop {
            if let Some(value) = probe.poll(Instant::now()) {
                break value;
            }
            assert!(Instant::now() < deadline, "disk probe failed to return");
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(value["path"], root.path().to_str().unwrap());
        assert!(value["total"].as_u64().unwrap() > 0);
    }

    #[test]
    fn stalled_probe_is_killed_and_never_blocks_parent() {
        let root = tempfile::tempdir().unwrap();
        let script = root.path().join("stall");
        std::fs::write(
            &script,
            "#!/bin/sh\nprintf '%s' \"$$\" > \"$3/pid\"\nexec sleep 30\n",
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut probe = DiskProbe::new(&script, root.path()).unwrap();
        let start = Instant::now();
        let pid_file = root.path().join("pid");
        while !pid_file.exists() {
            assert!(start.elapsed() < Duration::from_secs(3));
            assert!(probe.poll(Instant::now()).is_none());
            std::thread::sleep(Duration::from_millis(20));
        }
        let pid: i32 = std::fs::read_to_string(&pid_file).unwrap().parse().unwrap();
        while Path::new(&format!("/proc/{pid}")).exists() {
            assert!(
                start.elapsed() < Duration::from_secs(6),
                "stalled child was not reaped"
            );
            assert!(probe.poll(Instant::now()).is_none());
            std::thread::sleep(Duration::from_millis(30));
        }
        let before = Instant::now();
        drop(probe);
        assert!(before.elapsed() < Duration::from_secs(1));
        let link = root.path().join("link");
        symlink(&script, &link).unwrap();
        assert!(DiskProbe::new(&link, root.path()).is_err());
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(DiskProbe::new(&script, root.path()).is_err());
    }

    #[test]
    fn rejects_mutable_or_linked_ancestor_directories() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("bin");
        std::fs::create_dir(&dir).unwrap();
        let helper = dir.join("probe");
        std::fs::write(&helper, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(DiskProbe::new(&helper, root.path()).is_ok());
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(DiskProbe::new(&helper, root.path()).is_err());
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let linked = root.path().join("linked");
        symlink(&dir, &linked).unwrap();
        assert!(DiskProbe::new(&linked.join("probe"), root.path()).is_err());
    }
}
