#[cfg(target_os = "linux")]
mod linux {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::process::Command;
    use xcli_certificates::bundle::{publish, PublishError};

    fn certificate(root: &std::path::Path, id: &str) -> (Vec<u8>, Vec<u8>) {
        let cert = root.join(format!("cert-{id}.pem"));
        let key = root.join(format!("key-{id}.pem"));
        assert!(Command::new("/usr/bin/openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "2",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost",
                "-keyout"
            ])
            .arg(&key)
            .arg("-out")
            .arg(&cert)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
            .success());
        (std::fs::read(cert).unwrap(), std::fs::read(key).unwrap())
    }

    #[test]
    #[ignore = "requires root and an explicitly supplied unprivileged fixture account"]
    fn root_publishes_for_core_group_after_dropped_validation() {
        use std::os::unix::fs::MetadataExt;
        use xcli_certificates::bundle::publish_dropped;
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let uid: u32 = std::env::var("XCLI_TEST_CERT_UID")
            .unwrap()
            .parse()
            .unwrap();
        let gid: u32 = std::env::var("XCLI_TEST_CERT_GID")
            .unwrap()
            .parse()
            .unwrap();
        assert_ne!(uid, 0);
        assert_ne!(gid, 0);
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = certificate(dir.path(), "root");
        let target = dir.path().join("live.pem");
        publish_dropped(&target, "localhost", &cert, &key, uid, gid, gid).unwrap();
        let metadata = std::fs::metadata(&target).unwrap();
        assert_eq!(
            (metadata.uid(), metadata.gid(), metadata.mode() & 0o777),
            (0, gid, 0o640)
        );
        assert_eq!(
            publish_dropped(&target, "localhost", &cert, &key, uid, gid, 0),
            Err(PublishError::Unavailable)
        );
    }

    #[test]
    fn publishes_private_combined_pem_and_rejects_invalid_or_untrusted_updates() {
        let dir = tempfile::tempdir().unwrap();
        let (cert1, key1) = certificate(dir.path(), "one");
        let (cert2, key2) = certificate(dir.path(), "two");
        let target = dir.path().join("live.pem");
        publish(&target, "localhost", &cert1, &key1).unwrap();
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o640
        );
        let before = std::fs::read(&target).unwrap();
        assert!(before.starts_with(&cert1));
        assert!(before.ends_with(&key1));
        assert_eq!(
            publish(&target, "wrong.example", &cert2, &key2),
            Err(PublishError::Invalid)
        );
        assert_eq!(
            publish(&target, "localhost", &cert2, &key1),
            Err(PublishError::Invalid)
        );
        assert_eq!(std::fs::read(&target).unwrap(), before);
        let link = dir.path().join("link.pem");
        symlink(&target, &link).unwrap();
        assert_eq!(
            publish(&link, "localhost", &cert2, &key2),
            Err(PublishError::Unavailable)
        );
        assert_eq!(std::fs::read(&target).unwrap(), before);
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(dir.path().join(".xcli-cert.lock"))
            .unwrap();
        assert_eq!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        assert_eq!(
            publish(&target, "localhost", &cert2, &key2),
            Err(PublishError::Unavailable)
        );
        drop(lock);
        assert_eq!(std::fs::read(&target).unwrap(), before);
        publish(&target, "localhost", &cert2, &key2).unwrap();
        let after = std::fs::read(&target).unwrap();
        assert!(after.starts_with(&cert2));
        assert!(after.ends_with(&key2));
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            publish(&target, "localhost", &cert1, &key1),
            Err(PublishError::Unavailable)
        );
        assert_eq!(std::fs::read(&target).unwrap(), after);
    }
}
