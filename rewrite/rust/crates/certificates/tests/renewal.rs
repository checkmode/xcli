use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;
use xcli_certificates::renewal::{matches_lineage, read_pair, RenewalError};

fn fixture(root: &Path) {
    let live = root.join("live/example.test");
    let archive = root.join("archive/example.test");
    std::fs::create_dir_all(&live).unwrap();
    std::fs::create_dir_all(&archive).unwrap();
    std::fs::write(archive.join("fullchain1.pem"), b"synthetic certificate").unwrap();
    std::fs::write(archive.join("privkey1.pem"), b"synthetic private key").unwrap();
    std::fs::set_permissions(
        archive.join("privkey1.pem"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    symlink(
        "../../archive/example.test/fullchain1.pem",
        live.join("fullchain.pem"),
    )
    .unwrap();
    symlink(
        "../../archive/example.test/privkey1.pem",
        live.join("privkey.pem"),
    )
    .unwrap();
}

#[test]
fn selects_only_the_expected_global_hook_lineage() {
    let root = tempfile::tempdir().unwrap();
    let expected = root.path().join("live/example.test");
    let other = root.path().join("live/other.test");
    assert_eq!(
        matches_lineage(root.path(), "example.test", Some(&expected)),
        Ok(true)
    );
    assert_eq!(
        matches_lineage(root.path(), "example.test", Some(&other)),
        Ok(false)
    );
    assert_eq!(
        matches_lineage(root.path(), "example.test", None),
        Err(RenewalError::Invalid)
    );
    assert_eq!(
        matches_lineage(root.path(), "../other", Some(&other)),
        Err(RenewalError::Invalid)
    );
}

#[test]
fn reads_bounded_certbot_archive_but_refuses_escapes_or_untrusted_files() {
    let root = tempfile::tempdir().unwrap();
    fixture(root.path());
    let pair = read_pair(root.path(), "example.test").unwrap();
    assert_eq!(pair.certificate(), b"synthetic certificate");
    assert_eq!(pair.private_key(), b"synthetic private key");
    let live = root.path().join("live/example.test");
    let archive = root.path().join("archive/example.test");
    let external = root.path().join("external.pem");
    std::fs::write(&external, b"external").unwrap();
    std::fs::remove_file(live.join("privkey.pem")).unwrap();
    symlink(&external, live.join("privkey.pem")).unwrap();
    assert!(matches!(
        read_pair(root.path(), "example.test"),
        Err(RenewalError::Unavailable)
    ));
    std::fs::remove_file(live.join("privkey.pem")).unwrap();
    symlink(
        "../../archive/example.test/privkey1.pem",
        live.join("privkey.pem"),
    )
    .unwrap();
    std::fs::set_permissions(
        archive.join("privkey1.pem"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(matches!(
        read_pair(root.path(), "example.test"),
        Err(RenewalError::Unavailable)
    ));
    std::fs::set_permissions(
        archive.join("privkey1.pem"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    std::fs::hard_link(archive.join("privkey1.pem"), archive.join("extra.pem")).unwrap();
    assert!(matches!(
        read_pair(root.path(), "example.test"),
        Err(RenewalError::Unavailable)
    ));
    std::fs::remove_file(archive.join("extra.pem")).unwrap();
    std::fs::set_permissions(&archive, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(matches!(
        read_pair(root.path(), "example.test"),
        Err(RenewalError::Unavailable)
    ));
    std::fs::set_permissions(&archive, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(archive.join("fullchain1.pem"), vec![b'x'; 256 * 1024 + 1]).unwrap();
    assert!(matches!(
        read_pair(root.path(), "example.test"),
        Err(RenewalError::Unavailable)
    ));
}
