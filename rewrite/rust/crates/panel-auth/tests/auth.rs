use aes_gcm::{aead::AeadInPlace, Aes256Gcm, KeyInit, Nonce};
use base64::{engine::general_purpose::STANDARD, Engine};
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::Duration;
use xcli_auth_compat::verify_password;
use xcli_panel_auth::{AdminAuth, AuthError, PasswordChange, Reauthentication};

const HASH: &str = "000102030405060708090a0b0c0d0e0f:afc6691525faf48bd6fd7965166241e1deb78be6f8e199afd0406a9608658dbf";
const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

#[test]
fn totp_enrollment_recovery_and_disabling_are_transactional() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("panel.sqlite");
    fixture(&path, HASH);
    let key = [3; 32];
    let mut auth = AdminAuth::open(&path, key).unwrap();
    let first = auth
        .login(
            "admin",
            "fixture-password",
            "",
            "127.0.0.1",
            59,
            Duration::ZERO,
        )
        .unwrap();
    let other = auth
        .login(
            "admin",
            "fixture-password",
            "",
            "127.0.0.2",
            59,
            Duration::ZERO,
        )
        .unwrap();
    let credentials = || Reauthentication {
        password: "fixture-password",
        code: "",
    };
    let setup = auth
        .setup_totp(
            &first.cookie,
            &first.csrf,
            credentials(),
            59,
            Duration::ZERO,
        )
        .unwrap();
    assert_eq!(setup.secret.len(), 32);
    assert!(setup
        .secret
        .bytes()
        .all(|c| c.is_ascii_uppercase() || (b'2'..=b'7').contains(&c)));
    assert_eq!(setup.expires, 659);
    let db = Connection::open(&path).unwrap();
    let pending: String = db
        .query_row("SELECT pending FROM mfa WHERE id=1", [], |row| row.get(0))
        .unwrap();
    assert!(!pending.contains(setup.secret.as_str()));
    // A known test secret makes the RFC 6238 vector deterministic.
    db.execute(
        "UPDATE mfa SET pending=? WHERE id=1",
        [mfa_frame(&key, SECRET)],
    )
    .unwrap();
    let code = || Reauthentication {
        password: "fixture-password",
        code: "287082",
    };
    assert_eq!(
        auth.enable_totp(&other.cookie, &other.csrf, code(), 59, Duration::ZERO)
            .err(),
        Some(AuthError::Conflict)
    );
    db.execute_batch("CREATE TRIGGER reject_recovery BEFORE INSERT ON recovery_codes BEGIN SELECT RAISE(ABORT,'fail'); END;").unwrap();
    assert_eq!(
        auth.enable_totp(&first.cookie, &first.csrf, code(), 59, Duration::ZERO)
            .err(),
        Some(AuthError::Unavailable)
    );
    assert!(!auth.security_status(&first.cookie, 59).unwrap().enabled);
    assert!(auth.session(&other.cookie, None, 59).is_ok());
    db.execute_batch("DROP TRIGGER reject_recovery;").unwrap();
    let original = auth
        .enable_totp(
            &first.cookie,
            &first.csrf,
            code(),
            59,
            Duration::from_secs(1),
        )
        .unwrap();
    assert_eq!(original.len(), 10);
    assert!(auth.security_status(&first.cookie, 59).unwrap().enabled);
    assert_eq!(
        auth.security_status(&first.cookie, 59)
            .unwrap()
            .recovery_remaining,
        10
    );
    assert!(matches!(
        auth.session(&other.cookie, None, 59),
        Err(AuthError::Unauthorized)
    ));
    let refresh = Reauthentication {
        password: "fixture-password",
        code: &original[0],
    };
    let replacement = auth
        .regenerate_recovery(
            &first.cookie,
            &first.csrf,
            refresh,
            59,
            Duration::from_secs(2),
        )
        .unwrap();
    assert_eq!(replacement.len(), 10);
    let stale = Reauthentication {
        password: "fixture-password",
        code: &original[0],
    };
    assert_eq!(
        auth.disable_totp(
            &first.cookie,
            &first.csrf,
            stale,
            59,
            Duration::from_secs(3)
        ),
        Err(AuthError::InvalidCredentials)
    );
    let valid = Reauthentication {
        password: "fixture-password",
        code: &replacement[0],
    };
    auth.disable_totp(
        &first.cookie,
        &first.csrf,
        valid,
        59,
        Duration::from_secs(4),
    )
    .unwrap();
    assert!(matches!(
        auth.session(&first.cookie, None, 59),
        Err(AuthError::Unauthorized)
    ));
    assert_eq!(
        db.query_row("SELECT enabled FROM mfa WHERE id=1", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM recovery_codes", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn totp_enrollment_attempts_are_rate_limited() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("panel.sqlite");
    fixture(&path, HASH);
    let key = [3; 32];
    let mut auth = AdminAuth::open(&path, key).unwrap();
    let login = auth
        .login(
            "admin",
            "fixture-password",
            "",
            "127.0.0.1",
            59,
            Duration::ZERO,
        )
        .unwrap();
    auth.setup_totp(
        &login.cookie,
        &login.csrf,
        Reauthentication {
            password: "fixture-password",
            code: "",
        },
        59,
        Duration::ZERO,
    )
    .unwrap();
    let db = Connection::open(&path).unwrap();
    db.execute(
        "UPDATE mfa SET pending=? WHERE id=1",
        [mfa_frame(&key, SECRET)],
    )
    .unwrap();
    for _ in 0..8 {
        assert_eq!(
            auth.enable_totp(
                &login.cookie,
                &login.csrf,
                Reauthentication {
                    password: "fixture-password",
                    code: "000000"
                },
                59,
                Duration::ZERO
            )
            .err(),
            Some(AuthError::InvalidCredentials)
        );
    }
    assert_eq!(
        auth.enable_totp(
            &login.cookie,
            &login.csrf,
            Reauthentication {
                password: "fixture-password",
                code: "287082"
            },
            59,
            Duration::from_secs(1)
        )
        .err(),
        Some(AuthError::RateLimited)
    );
    assert!(auth
        .enable_totp(
            &login.cookie,
            &login.csrf,
            Reauthentication {
                password: "fixture-password",
                code: "287082"
            },
            59,
            Duration::from_secs(901)
        )
        .is_ok());
}

#[test]
fn password_change_revalidates_mfa_and_rolls_back_recovery_on_failure() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("panel.sqlite");
    fixture(&path, HASH);
    let key = [3; 32];
    let db = Connection::open(&path).unwrap();
    db.execute(
        "UPDATE mfa SET enabled=1,secret=? WHERE id=1",
        [mfa_frame(&key, SECRET)],
    )
    .unwrap();
    for code in ["login-fixture", "confirm-fixture"] {
        db.execute(
            "INSERT INTO recovery_codes(hash) VALUES(?)",
            [hex::encode(Sha256::digest(code.as_bytes()))],
        )
        .unwrap();
    }
    let mut auth = AdminAuth::open(&path, key).unwrap();
    let login = auth
        .login(
            "admin",
            "fixture-password",
            "login-fixture",
            "127.0.0.1",
            59,
            Duration::ZERO,
        )
        .unwrap();
    let new_password = "new-fixture-password";
    assert_eq!(
        auth.change_password(
            &login.cookie,
            "bad",
            PasswordChange {
                current: "fixture-password",
                next: new_password,
                code: "confirm-fixture"
            },
            59,
            Duration::from_secs(1)
        ),
        Err(AuthError::Csrf)
    );
    assert_eq!(
        auth.change_password(
            &login.cookie,
            &login.csrf,
            PasswordChange {
                current: "bad",
                next: new_password,
                code: "confirm-fixture"
            },
            59,
            Duration::from_secs(1)
        ),
        Err(AuthError::InvalidCredentials)
    );
    db.execute_batch("CREATE TRIGGER reject_password BEFORE UPDATE ON admin BEGIN SELECT RAISE(ABORT,'fail'); END;").unwrap();
    assert_eq!(
        auth.change_password(
            &login.cookie,
            &login.csrf,
            PasswordChange {
                current: "fixture-password",
                next: new_password,
                code: "confirm-fixture"
            },
            59,
            Duration::from_secs(2)
        ),
        Err(AuthError::Unavailable)
    );
    assert_eq!(
        db.query_row(
            "SELECT used FROM recovery_codes WHERE hash=?",
            [hex::encode(Sha256::digest(b"confirm-fixture"))],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    assert!(auth.session(&login.cookie, None, 59).is_ok());
    db.execute_batch("DROP TRIGGER reject_password;").unwrap();
    auth.change_password(
        &login.cookie,
        &login.csrf,
        PasswordChange {
            current: "fixture-password",
            next: new_password,
            code: "confirm-fixture",
        },
        59,
        Duration::from_secs(3),
    )
    .unwrap();
    assert!(matches!(
        auth.session(&login.cookie, None, 59),
        Err(AuthError::Unauthorized)
    ));
    let hash: String = db
        .query_row("SELECT password FROM admin WHERE id=1", [], |r| r.get(0))
        .unwrap();
    assert!(verify_password(new_password, &hash));
    assert!(!verify_password("fixture-password", &hash));
    assert_eq!(
        db.query_row(
            "SELECT used FROM recovery_codes WHERE hash=?",
            [hex::encode(Sha256::digest(b"confirm-fixture"))],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    assert!(auth
        .login(
            "admin",
            new_password,
            "287082",
            "127.0.0.1",
            59,
            Duration::from_secs(4)
        )
        .is_ok());
}

#[test]
fn password_confirmation_attempts_are_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("panel.sqlite");
    fixture(&path, HASH);
    let mut auth = AdminAuth::open(&path, [0; 32]).unwrap();
    let login = auth
        .login(
            "admin",
            "fixture-password",
            "",
            "127.0.0.1",
            1000,
            Duration::ZERO,
        )
        .unwrap();
    assert_eq!(
        auth.change_password(
            &login.cookie,
            &login.csrf,
            PasswordChange {
                current: "fixture-password",
                next: "short",
                code: ""
            },
            1000,
            Duration::ZERO
        ),
        Err(AuthError::InvalidInput)
    );
    for _ in 0..8 {
        assert_eq!(
            auth.change_password(
                &login.cookie,
                &login.csrf,
                PasswordChange {
                    current: "bad",
                    next: "new-fixture-password",
                    code: ""
                },
                1000,
                Duration::ZERO
            ),
            Err(AuthError::InvalidCredentials)
        );
    }
    assert_eq!(
        auth.change_password(
            &login.cookie,
            &login.csrf,
            PasswordChange {
                current: "fixture-password",
                next: "new-fixture-password",
                code: ""
            },
            1001,
            Duration::from_secs(1)
        ),
        Err(AuthError::RateLimited)
    );
    assert!(auth
        .change_password(
            &login.cookie,
            &login.csrf,
            PasswordChange {
                current: "fixture-password",
                next: "new-fixture-password",
                code: ""
            },
            1901,
            Duration::from_secs(901)
        )
        .is_ok());
}

fn fixture(path: &Path, password_hash: &str) {
    let db = Connection::open(path).unwrap();
    db.execute_batch("CREATE TABLE admin(id INTEGER PRIMARY KEY,password TEXT NOT NULL);
        CREATE TABLE sessions(hash TEXT PRIMARY KEY,csrf TEXT NOT NULL,expires INTEGER NOT NULL);
        CREATE TABLE mfa(id INTEGER PRIMARY KEY,enabled INTEGER NOT NULL,secret TEXT NOT NULL,last_step INTEGER NOT NULL,
            pending TEXT NOT NULL DEFAULT '',pending_expires INTEGER NOT NULL DEFAULT 0,pending_session TEXT NOT NULL DEFAULT '');
        CREATE TABLE mfa_sessions(hash TEXT PRIMARY KEY);
        CREATE TABLE recovery_codes(hash TEXT PRIMARY KEY,used INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE events(id INTEGER PRIMARY KEY,ts INTEGER NOT NULL,action TEXT NOT NULL,detail TEXT NOT NULL);").unwrap();
    db.execute("INSERT INTO admin VALUES(1,?)", [password_hash])
        .unwrap();
    db.execute(
        "INSERT INTO mfa(id,enabled,secret,last_step) VALUES(1,0,'',-1)",
        [],
    )
    .unwrap();
}

fn mfa_frame(key: &[u8; 32], secret: &str) -> String {
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    let nonce = [7u8; 12];
    let mut data = secret.as_bytes().to_vec();
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), b"xcli:mfa:v1", &mut data)
        .unwrap();
    let mut out = b"XGB1".to_vec();
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&data);
    STANDARD.encode(out)
}

#[test]
fn login_session_csrf_expiry_and_logout() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("panel.sqlite");
    fixture(&path, HASH);
    let mut auth = AdminAuth::open(&path, [0; 32]).unwrap();
    assert!(matches!(
        auth.login("admin", "wrong", "", "127.0.0.1", 1000, Duration::ZERO),
        Err(AuthError::InvalidCredentials)
    ));
    let login = auth
        .login(
            "admin",
            "fixture-password",
            "",
            "127.0.0.1",
            1001,
            Duration::from_secs(1),
        )
        .unwrap();
    assert_eq!(login.cookie.len(), 43);
    assert_eq!(login.csrf.len(), 43);
    assert!(matches!(
        auth.session(&login.cookie, Some("wrong"), 1002),
        Err(AuthError::Csrf)
    ));
    assert_eq!(
        auth.session(&login.cookie, Some(&login.csrf), 1002)
            .unwrap()
            .csrf,
        login.csrf
    );
    assert!(matches!(
        auth.session(&login.cookie, None, 1001 + 8 * 3600),
        Err(AuthError::Unauthorized)
    ));
    let db = Connection::open(&path).unwrap();
    let stored: String = db
        .query_row("SELECT hash FROM sessions", [], |r| r.get(0))
        .unwrap();
    assert_ne!(stored, login.cookie);
    assert_eq!(stored, hex::encode(Sha256::digest(login.cookie.as_bytes())));
    drop(db);
    auth.logout(&login.cookie, &login.csrf, 1002).unwrap();
    assert!(matches!(
        auth.session(&login.cookie, None, 1003),
        Err(AuthError::Unauthorized)
    ));
}

#[test]
fn totp_replay_and_recovery_code_are_transactional() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("panel.sqlite");
    fixture(&path, HASH);
    let key = [3; 32];
    let frame = mfa_frame(&key, SECRET);
    let recovery = "fixture-recovery";
    let db = Connection::open(&path).unwrap();
    db.execute("UPDATE mfa SET enabled=1,secret=? WHERE id=1", [frame])
        .unwrap();
    db.execute(
        "INSERT INTO recovery_codes(hash) VALUES(?)",
        [hex::encode(Sha256::digest(recovery.as_bytes()))],
    )
    .unwrap();
    drop(db);
    let mut auth = AdminAuth::open(&path, key).unwrap();
    let login = auth
        .login(
            "admin",
            "fixture-password",
            "287082",
            "127.0.0.1",
            59,
            Duration::ZERO,
        )
        .unwrap();
    assert!(auth.session(&login.cookie, None, 59).is_ok());
    assert!(matches!(
        auth.login(
            "admin",
            "fixture-password",
            "287082",
            "127.0.0.1",
            59,
            Duration::from_secs(1)
        ),
        Err(AuthError::InvalidCredentials)
    ));
    assert!(auth
        .login(
            "admin",
            "fixture-password",
            recovery,
            "127.0.0.1",
            59,
            Duration::from_secs(2)
        )
        .is_ok());
    assert!(matches!(
        auth.login(
            "admin",
            "fixture-password",
            recovery,
            "127.0.0.1",
            59,
            Duration::from_secs(3)
        ),
        Err(AuthError::InvalidCredentials)
    ));
    let db = Connection::open(&path).unwrap();
    assert_eq!(
        db.query_row("SELECT last_step FROM mfa", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        db.query_row("SELECT used FROM recovery_codes", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[test]
fn failed_attempts_stay_limited_until_window_expires() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("panel.sqlite");
    fixture(&path, "invalid-hash");
    let mut auth = AdminAuth::open(&path, [0; 32]).unwrap();
    for _ in 0..8 {
        assert!(matches!(
            auth.login("admin", "bad", "", "127.0.0.1", 1000, Duration::ZERO),
            Err(AuthError::InvalidCredentials)
        ));
    }
    assert!(matches!(
        auth.login(
            "admin",
            "bad",
            "",
            "127.0.0.1",
            1900,
            Duration::from_secs(900)
        ),
        Err(AuthError::RateLimited)
    ));
    assert!(matches!(
        auth.login(
            "admin",
            "bad",
            "",
            "127.0.0.1",
            1901,
            Duration::from_secs(901)
        ),
        Err(AuthError::InvalidCredentials)
    ));
    assert!(matches!(
        auth.login(
            "admin",
            "bad",
            "",
            "not-an-ip",
            1901,
            Duration::from_secs(901)
        ),
        Err(AuthError::InvalidInput)
    ));
    for _ in 0..8 {
        assert!(matches!(
            auth.login(
                "admin",
                "bad",
                "",
                "0:0:0:0:0:0:0:1",
                2000,
                Duration::from_secs(1000)
            ),
            Err(AuthError::InvalidCredentials)
        ));
    }
    assert!(matches!(
        auth.login("admin", "bad", "", "::1", 2000, Duration::from_secs(1000)),
        Err(AuthError::RateLimited)
    ));
}

#[test]
fn failed_session_write_does_not_consume_totp_or_recovery_code() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("panel.sqlite");
    fixture(&path, HASH);
    let key = [3; 32];
    let frame = mfa_frame(&key, SECRET);
    let recovery = "fixture-recovery";
    let db = Connection::open(&path).unwrap();
    db.execute("UPDATE mfa SET enabled=1,secret=? WHERE id=1", [frame])
        .unwrap();
    db.execute(
        "INSERT INTO recovery_codes(hash) VALUES(?)",
        [hex::encode(Sha256::digest(recovery.as_bytes()))],
    )
    .unwrap();
    db.execute_batch("CREATE TRIGGER fixture_failure BEFORE INSERT ON sessions BEGIN SELECT RAISE(ABORT, 'fixture failure'); END;").unwrap();
    drop(db);
    let mut auth = AdminAuth::open(&path, key).unwrap();
    assert!(matches!(
        auth.login(
            "admin",
            "fixture-password",
            "287082",
            "127.0.0.1",
            59,
            Duration::ZERO
        ),
        Err(AuthError::Unavailable)
    ));
    assert!(matches!(
        auth.login(
            "admin",
            "fixture-password",
            recovery,
            "127.0.0.1",
            59,
            Duration::from_secs(1)
        ),
        Err(AuthError::Unavailable)
    ));
    let db = Connection::open(&path).unwrap();
    assert_eq!(
        db.query_row("SELECT last_step FROM mfa", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        -1
    );
    assert_eq!(
        db.query_row("SELECT used FROM recovery_codes", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn enabling_mfa_rejects_sessions_without_second_factor_proof() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("panel.sqlite");
    fixture(&path, HASH);
    let mut auth = AdminAuth::open(&path, [0; 32]).unwrap();
    let login = auth
        .login(
            "admin",
            "fixture-password",
            "",
            "127.0.0.1",
            1000,
            Duration::ZERO,
        )
        .unwrap();
    let db = Connection::open(&path).unwrap();
    db.execute("UPDATE mfa SET enabled=1 WHERE id=1", [])
        .unwrap();
    db.execute("DELETE FROM mfa_sessions", []).unwrap();
    drop(db);
    assert!(matches!(
        auth.session(&login.cookie, None, 1001),
        Err(AuthError::Unauthorized)
    ));
}

#[test]
fn broken_or_missing_security_state_never_authenticates() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("panel.sqlite");
    fixture(&path, HASH);
    let db = Connection::open(&path).unwrap();
    db.execute(
        "UPDATE mfa SET enabled=1,secret=?",
        params![STANDARD.encode(b"invalid")],
    )
    .unwrap();
    drop(db);
    let mut auth = AdminAuth::open(&path, [0; 32]).unwrap();
    assert!(matches!(
        auth.login(
            "admin",
            "fixture-password",
            "123456",
            "127.0.0.1",
            1000,
            Duration::ZERO
        ),
        Err(AuthError::Unavailable)
    ));
    assert!(matches!(
        AdminAuth::open(&dir.path().join("missing.sqlite"), [0; 32]),
        Err(AuthError::Unavailable)
    ));
}

#[test]
fn confirmed_operation_rolls_back_recovery_code_and_writes_on_failure() {
    use xcli_panel_auth::ConfirmedError;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("confirmed.sqlite");
    fixture(&path, HASH);
    let key = [3; 32];
    let db = Connection::open(&path).unwrap();
    db.execute(
        "UPDATE mfa SET enabled=1,secret=?,last_step=-1 WHERE id=1",
        [mfa_frame(&key, SECRET)],
    )
    .unwrap();
    let recovery = "synthetic-recovery-code";
    let hash = hex::encode(Sha256::digest(recovery.as_bytes()));
    db.execute("INSERT INTO recovery_codes(hash,used) VALUES(?,0)", [&hash])
        .unwrap();
    db.execute_batch("CREATE TABLE confirmed_fixture(value TEXT NOT NULL);")
        .unwrap();
    let mut auth = AdminAuth::open(&path, key).unwrap();
    let login = auth
        .login(
            "admin",
            "fixture-password",
            "287082",
            "127.0.0.1",
            59,
            Duration::ZERO,
        )
        .unwrap();
    let confirmation = || Reauthentication {
        password: "fixture-password",
        code: recovery,
    };
    let failed = auth.confirmed(
        &login.cookie,
        &login.csrf,
        confirmation(),
        59,
        Duration::from_secs(1),
        |tx| {
            tx.execute("INSERT INTO confirmed_fixture VALUES('will roll back')", [])
                .unwrap();
            Err::<(), _>("rejected")
        },
    );
    assert_eq!(failed, Err(ConfirmedError::Operation("rejected")));
    assert_eq!(
        db.query_row(
            "SELECT used FROM recovery_codes WHERE hash=?",
            [&hash],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM confirmed_fixture", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    let success = auth.confirmed(
        &login.cookie,
        &login.csrf,
        confirmation(),
        59,
        Duration::from_secs(2),
        |tx| {
            tx.execute("INSERT INTO confirmed_fixture VALUES('committed')", [])
                .unwrap();
            Ok::<_, &str>(())
        },
    );
    assert_eq!(success, Ok(()));
    assert_eq!(
        db.query_row(
            "SELECT used FROM recovery_codes WHERE hash=?",
            [&hash],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM confirmed_fixture", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    let reused = auth.confirmed(
        &login.cookie,
        &login.csrf,
        confirmation(),
        59,
        Duration::from_secs(3),
        |_| Ok::<_, &str>(()),
    );
    assert_eq!(
        reused,
        Err(ConfirmedError::Auth(AuthError::InvalidCredentials))
    );
}
