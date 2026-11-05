use xcli_auth_compat::{open_xgb1, seal_xgb1, verify_password, verify_totp};

#[test]
fn verifies_legacy_scrypt_hash() {
    // Python hashlib.scrypt: n=16384, r=8, p=1, salt=00..0f.
    let encoded = "000102030405060708090a0b0c0d0e0f:afc6691525faf48bd6fd7965166241e1deb78be6f8e199afd0406a9608658dbf";
    assert!(verify_password("fixture-password", encoded));
    assert!(!verify_password("other", encoded));
    assert!(!verify_password("fixture-password", "invalid"));
    assert!(verify_password("fixture-password", &encoded.to_uppercase()));
}

#[test]
fn totp_window_and_replay_match_existing_rules() {
    // RFC 6238 SHA-1 secret; six-digit suffixes of the RFC examples.
    let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    assert_eq!(verify_totp(secret, "287082", 59, -1).unwrap(), Some(1));
    assert_eq!(verify_totp(secret, "287082", 59, 1).unwrap(), None);
    assert_eq!(
        verify_totp(secret, "081804", 1_111_111_109, -1).unwrap(),
        Some(37_037_036)
    );
    assert_eq!(verify_totp(secret, "bad", 59, -1).unwrap(), None);
    assert!(verify_totp("invalid!", "123456", 59, -1).is_err());
}

#[test]
fn decrypts_python_aes_gcm_legacy_frame_and_rejects_tampering() {
    // Fixture from Python cryptography AESGCM with nonce=00..0b and key=00..1f.
    let data = hex::decode("58474231000102030405060708090a0b71953edcfc14203feb8e2f1ee88e3c490d40854c9cd6864bc809c7c082b9203d").unwrap();
    let key: Vec<u8> = (0..32).collect();
    assert_eq!(
        &*open_xgb1(&data, &key, b"xcli:mfa:v1").unwrap(),
        b"JBSWY3DPEHPK3PXP"
    );
    assert!(open_xgb1(&data, &key, b"wrong context").is_err());
    let mut corrupt = data;
    corrupt[16] ^= 1;
    assert!(open_xgb1(&corrupt, &key, b"xcli:mfa:v1").is_err());
    assert!(open_xgb1(&corrupt[..20], &key, b"xcli:mfa:v1").is_err());
}

#[test]
fn sealed_envelopes_use_fresh_nonces_and_authenticated_context() {
    let first = seal_xgb1(b"synthetic", &[9; 32], b"xcli:backup:v1").unwrap();
    let second = seal_xgb1(b"synthetic", &[9; 32], b"xcli:backup:v1").unwrap();
    assert_ne!(&first[4..16], &second[4..16]);
    assert_eq!(
        &*open_xgb1(&first, &[9; 32], b"xcli:backup:v1").unwrap(),
        b"synthetic"
    );
    assert!(open_xgb1(&first, &[9; 32], b"wrong").is_err());
}
