//! Legacy-compatible admin login and session transactions.
//!
//! This is not an HTTP service. Its caller must enforce same-origin and CSRF
//! on mutations, trust client IPs only from a configured reverse proxy, and
//! serialize all authorization and related database mutations.
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use rusqlite::config::DbConfig;
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;
use subtle::ConstantTimeEq;
use xcli_auth_compat::{hash_password, open_xgb1, seal_xgb1, verify_password, verify_totp};
use zeroize::Zeroizing;

#[derive(Debug, PartialEq, Eq)]
pub enum AuthError {
    InvalidInput,
    InvalidCredentials,
    RateLimited,
    Unauthorized,
    Csrf,
    Conflict,
    Unavailable,
}
#[derive(Debug, PartialEq, Eq)]
pub enum ConfirmedError<E> {
    Auth(AuthError),
    Operation(E),
}
type Result<T> = std::result::Result<T, AuthError>;

pub struct Login {
    pub cookie: String,
    pub csrf: String,
}
pub struct Session {
    pub csrf: String,
}
pub struct PasswordChange<'a> {
    pub current: &'a str,
    pub next: &'a str,
    pub code: &'a str,
}
pub struct SecurityStatus {
    pub enabled: bool,
    pub recovery_remaining: i64,
}
pub struct Reauthentication<'a> {
    pub password: &'a str,
    pub code: &'a str,
}
pub struct TotpSetup {
    pub secret: Zeroizing<String>,
    pub expires: i64,
}

fn digest(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}
fn random_token() -> Result<String> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(bytes.as_mut()).map_err(|_| AuthError::Unavailable)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes.as_ref()))
}
fn reserve_attempt(
    rate: &mut HashMap<String, VecDeque<Duration>>,
    token: &str,
    monotonic: Duration,
) -> Result<()> {
    rate.retain(|_, attempts| {
        while attempts.front().is_some_and(|v| {
            monotonic
                .checked_sub(*v)
                .is_some_and(|age| age > Duration::from_secs(900))
        }) {
            attempts.pop_front();
        }
        !attempts.is_empty()
    });
    if (!rate.contains_key(token) && rate.len() >= 10_000)
        || rate.get(token).is_some_and(|attempts| attempts.len() >= 8)
    {
        return Err(AuthError::RateLimited);
    }
    rate.entry(token.to_owned())
        .or_default()
        .push_back(monotonic);
    Ok(())
}
fn totp_secret() -> Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new([0u8; 20]);
    getrandom::fill(bytes.as_mut()).map_err(|_| AuthError::Unavailable)?;
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut result = Zeroizing::new(String::with_capacity(32));
    let (mut acc, mut bits) = (0u32, 0u32);
    for byte in bytes.iter() {
        acc = acc.wrapping_shl(8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            result.push(alphabet[((acc >> bits) & 31) as usize] as char);
        }
    }
    Ok(result)
}
fn make_recovery(tx: &Transaction<'_>) -> Result<Zeroizing<Vec<String>>> {
    tx.execute("DELETE FROM recovery_codes", [])
        .map_err(|_| AuthError::Unavailable)?;
    let mut codes = Zeroizing::new(Vec::with_capacity(10));
    for _ in 0..10 {
        let mut random = Zeroizing::new([0u8; 16]);
        getrandom::fill(random.as_mut()).map_err(|_| AuthError::Unavailable)?;
        let raw = Zeroizing::new(hex::encode(random.as_ref()));
        let code = format!(
            "{}-{}-{}-{}",
            &raw[0..8],
            &raw[8..16],
            &raw[16..24],
            &raw[24..32]
        );
        tx.execute(
            "INSERT INTO recovery_codes(hash) VALUES(?)",
            [digest(&code)],
        )
        .map_err(|_| AuthError::Unavailable)?;
        codes.push(code);
    }
    Ok(codes)
}
fn audit(tx: &Transaction<'_>, now: i64, action: &str) -> Result<()> {
    tx.execute(
        "INSERT INTO events(ts,action,detail) VALUES(?,?,'')",
        params![now, action],
    )
    .map_err(|_| AuthError::Unavailable)?;
    tx.execute(
        "DELETE FROM events WHERE id < (SELECT COALESCE(MAX(id),0)-2000 FROM events)",
        [],
    )
    .map_err(|_| AuthError::Unavailable)?;
    Ok(())
}

pub struct AdminAuth {
    db: Connection,
    key: Zeroizing<[u8; 32]>,
    rate: HashMap<String, VecDeque<Duration>>,
    stepup_rate: HashMap<String, VecDeque<Duration>>,
    enroll_rate: HashMap<String, VecDeque<Duration>>,
}

impl AdminAuth {
    /// Opens an existing database only. The caller must ensure the old panel is
    /// stopped before allowing this implementation to write to production data.
    pub fn open(path: &Path, key: [u8; 32]) -> Result<Self> {
        if std::fs::symlink_metadata(path)
            .map_err(|_| AuthError::Unavailable)?
            .file_type()
            .is_symlink()
        {
            return Err(AuthError::Unavailable);
        }
        let name = path.file_name().ok_or(AuthError::Unavailable)?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let resolved = std::fs::canonicalize(parent)
            .map_err(|_| AuthError::Unavailable)?
            .join(name);
        let db = Connection::open_with_flags(
            resolved,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_| AuthError::Unavailable)?;
        db.busy_timeout(Duration::from_secs(15))
            .map_err(|_| AuthError::Unavailable)?;
        db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;")
            .map_err(|_| AuthError::Unavailable)?;
        db.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
            .map_err(|_| AuthError::Unavailable)?;
        Ok(Self {
            db,
            key: Zeroizing::new(key),
            rate: HashMap::new(),
            stepup_rate: HashMap::new(),
            enroll_rate: HashMap::new(),
        })
    }

    fn second_factor(tx: &Transaction<'_>, key: &[u8; 32], code: &str, now: i64) -> Result<bool> {
        let (enabled, encrypted, last_step): (i64, String, i64) = tx
            .query_row(
                "SELECT enabled,secret,last_step FROM mfa WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map_err(|_| AuthError::Unavailable)?;
        if enabled == 0 {
            return Ok(true);
        }
        let encrypted = STANDARD
            .decode(encrypted)
            .map_err(|_| AuthError::Unavailable)?;
        let secret =
            open_xgb1(&encrypted, key, b"xcli:mfa:v1").map_err(|_| AuthError::Unavailable)?;
        let secret = std::str::from_utf8(&secret).map_err(|_| AuthError::Unavailable)?;
        if let Some(step) =
            verify_totp(secret, code, now, last_step).map_err(|_| AuthError::Unavailable)?
        {
            tx.execute("UPDATE mfa SET last_step=? WHERE id=1", [step])
                .map_err(|_| AuthError::Unavailable)?;
            return Ok(true);
        }
        let hash = digest(code);
        let count = tx
            .execute(
                "UPDATE recovery_codes SET used=1 WHERE hash=? AND used=0",
                [hash],
            )
            .map_err(|_| AuthError::Unavailable)?;
        Ok(count == 1)
    }

    fn confirm_admin(
        tx: &Transaction<'_>,
        key: &[u8; 32],
        input: &Reauthentication<'_>,
        now: i64,
    ) -> Result<()> {
        let stored: Option<String> = tx
            .query_row("SELECT password FROM admin WHERE id=1", [], |row| {
                row.get(0)
            })
            .optional()
            .map_err(|_| AuthError::Unavailable)?;
        if !stored
            .as_deref()
            .is_some_and(|hash| verify_password(input.password, hash))
            || !Self::second_factor(tx, key, input.code, now)?
        {
            return Err(AuthError::InvalidCredentials);
        }
        Ok(())
    }

    fn validate_confirmation(input: &Reauthentication<'_>, now: i64) -> Result<()> {
        if input.password.chars().count() > 256 || input.code.chars().count() > 128 || now < 0 {
            return Err(AuthError::InvalidInput);
        }
        Ok(())
    }

    /// Reauthenticate and perform a related database operation atomically.
    /// The caller must check the trusted origin and hold the shared mutation
    /// lock. If the operation fails, TOTP/recovery consumption is rolled back.
    pub fn confirmed<T, E>(
        &mut self,
        cookie: &str,
        csrf: &str,
        input: Reauthentication<'_>,
        now: i64,
        monotonic: Duration,
        operation: impl FnOnce(&Transaction<'_>) -> std::result::Result<T, E>,
    ) -> std::result::Result<T, ConfirmedError<E>> {
        Self::validate_confirmation(&input, now).map_err(ConfirmedError::Auth)?;
        self.session(cookie, Some(csrf), now)
            .map_err(ConfirmedError::Auth)?;
        let token_hash = digest(cookie);
        reserve_attempt(&mut self.stepup_rate, &token_hash, monotonic)
            .map_err(ConfirmedError::Auth)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ConfirmedError::Auth(AuthError::Unavailable))?;
        Self::confirm_admin(&tx, &self.key, &input, now).map_err(ConfirmedError::Auth)?;
        let result = operation(&tx).map_err(ConfirmedError::Operation)?;
        tx.commit()
            .map_err(|_| ConfirmedError::Auth(AuthError::Unavailable))?;
        self.stepup_rate.remove(&token_hash);
        Ok(result)
    }

    /// Attempts and TOTP/recovery-code use are serialized with session writes.
    /// `ip` must be derived by the trusted HTTP boundary, not from user input.
    pub fn login(
        &mut self,
        username: &str,
        password: &str,
        code: &str,
        ip: &str,
        now: i64,
        monotonic: Duration,
    ) -> Result<Login> {
        if username.chars().count() > 64 || password.chars().count() > 256 || now < 0 {
            return Err(AuthError::InvalidInput);
        }
        let ip = ip
            .parse::<IpAddr>()
            .map_err(|_| AuthError::InvalidInput)?
            .to_string();
        self.rate.retain(|_, attempts| {
            while attempts.front().is_some_and(|v| {
                monotonic
                    .checked_sub(*v)
                    .is_some_and(|age| age > Duration::from_secs(900))
            }) {
                attempts.pop_front();
            }
            !attempts.is_empty()
        });
        if !self.rate.contains_key(&ip) && self.rate.len() >= 10_000 {
            return Err(AuthError::RateLimited);
        }
        if self.rate.get(&ip).is_some_and(|v| v.len() >= 8) {
            return Err(AuthError::RateLimited);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| AuthError::Unavailable)?;
        let hash: Option<String> = tx
            .query_row("SELECT password FROM admin WHERE id=1", [], |r| r.get(0))
            .optional()
            .map_err(|_| AuthError::Unavailable)?;
        let mut valid = hash
            .as_deref()
            .is_some_and(|v| verify_password(password, v))
            && username == "admin";
        if valid {
            if code.chars().count() > 128 {
                return Err(AuthError::InvalidInput);
            }
            valid = Self::second_factor(&tx, &self.key, code, now)?;
        }
        if !valid {
            tx.execute(
                "INSERT INTO events(ts,action,detail) VALUES(?,?,?)",
                params![now, "login_failed", &ip],
            )
            .map_err(|_| AuthError::Unavailable)?;
            tx.execute(
                "DELETE FROM events WHERE id < (SELECT COALESCE(MAX(id),0)-2000 FROM events)",
                [],
            )
            .map_err(|_| AuthError::Unavailable)?;
            tx.commit().map_err(|_| AuthError::Unavailable)?;
            self.rate.entry(ip).or_default().push_back(monotonic);
            return Err(AuthError::InvalidCredentials);
        }
        let cookie = random_token()?;
        let csrf = random_token()?;
        let hash = digest(&cookie);
        let expires = now.checked_add(8 * 3600).ok_or(AuthError::Unavailable)?;
        tx.execute("DELETE FROM sessions WHERE expires<?", [now])
            .map_err(|_| AuthError::Unavailable)?;
        tx.execute(
            "INSERT INTO sessions VALUES(?,?,?)",
            params![hash, csrf, expires],
        )
        .map_err(|_| AuthError::Unavailable)?;
        tx.execute(
            "DELETE FROM mfa_sessions WHERE hash NOT IN (SELECT hash FROM sessions)",
            [],
        )
        .map_err(|_| AuthError::Unavailable)?;
        tx.execute("INSERT INTO mfa_sessions VALUES(?)", [digest(&cookie)])
            .map_err(|_| AuthError::Unavailable)?;
        tx.execute(
            "INSERT INTO events(ts,action,detail) VALUES(?,?,?)",
            params![now, "login", &ip],
        )
        .map_err(|_| AuthError::Unavailable)?;
        tx.execute(
            "DELETE FROM events WHERE id < (SELECT COALESCE(MAX(id),0)-2000 FROM events)",
            [],
        )
        .map_err(|_| AuthError::Unavailable)?;
        tx.commit().map_err(|_| AuthError::Unavailable)?;
        self.rate.remove(&ip);
        Ok(Login { cookie, csrf })
    }

    pub fn session(&self, cookie: &str, csrf: Option<&str>, now: i64) -> Result<Session> {
        if cookie.len() != 43 {
            return Err(AuthError::Unauthorized);
        }
        let hash = digest(cookie);
        let expected: Option<String> = self
            .db
            .query_row(
                "SELECT csrf FROM sessions WHERE hash=? AND expires>?",
                params![hash, now],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| AuthError::Unavailable)?;
        let expected = expected.ok_or(AuthError::Unauthorized)?;
        let enabled: i64 = self
            .db
            .query_row("SELECT enabled FROM mfa WHERE id=1", [], |r| r.get(0))
            .map_err(|_| AuthError::Unavailable)?;
        if enabled != 0
            && !self
                .db
                .query_row(
                    "SELECT 1 FROM mfa_sessions WHERE hash=?",
                    [digest(cookie)],
                    |r| r.get::<_, i64>(0),
                )
                .optional()
                .map_err(|_| AuthError::Unavailable)?
                .is_some()
        {
            return Err(AuthError::Unauthorized);
        }
        if let Some(value) = csrf {
            if expected.len() != value.len()
                || !bool::from(expected.as_bytes().ct_eq(value.as_bytes()))
            {
                return Err(AuthError::Csrf);
            }
        }
        Ok(Session { csrf: expected })
    }

    pub fn logout(&mut self, cookie: &str, csrf: &str, now: i64) -> Result<()> {
        self.session(cookie, Some(csrf), now)?;
        self.db
            .execute("DELETE FROM sessions WHERE hash=?", [digest(cookie)])
            .map_err(|_| AuthError::Unavailable)?;
        Ok(())
    }

    pub fn security_status(&self, cookie: &str, now: i64) -> Result<SecurityStatus> {
        self.session(cookie, None, now)?;
        let enabled: i64 = self
            .db
            .query_row("SELECT enabled FROM mfa WHERE id=1", [], |row| row.get(0))
            .map_err(|_| AuthError::Unavailable)?;
        let recovery_remaining: i64 = self
            .db
            .query_row(
                "SELECT COUNT(*) FROM recovery_codes WHERE used=0",
                [],
                |row| row.get(0),
            )
            .map_err(|_| AuthError::Unavailable)?;
        Ok(SecurityStatus {
            enabled: enabled != 0,
            recovery_remaining,
        })
    }

    /// Begin a ten-minute enrollment bound to the current authenticated
    /// session. The caller must enforce trusted origin and the mutation lock.
    pub fn setup_totp(
        &mut self,
        cookie: &str,
        csrf: &str,
        input: Reauthentication<'_>,
        now: i64,
        monotonic: Duration,
    ) -> Result<TotpSetup> {
        Self::validate_confirmation(&input, now)?;
        self.session(cookie, Some(csrf), now)?;
        let hash = digest(cookie);
        reserve_attempt(&mut self.stepup_rate, &hash, monotonic)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| AuthError::Unavailable)?;
        let enabled: i64 = tx
            .query_row("SELECT enabled FROM mfa WHERE id=1", [], |row| row.get(0))
            .map_err(|_| AuthError::Unavailable)?;
        if enabled != 0 {
            return Err(AuthError::Conflict);
        }
        Self::confirm_admin(&tx, &self.key, &input, now)?;
        let secret = totp_secret()?;
        let encrypted = seal_xgb1(secret.as_bytes(), self.key.as_ref(), b"xcli:mfa:v1")
            .map_err(|_| AuthError::Unavailable)?;
        let expires = now.checked_add(600).ok_or(AuthError::Unavailable)?;
        tx.execute(
            "UPDATE mfa SET pending=?,pending_expires=?,pending_session=? WHERE id=1",
            params![STANDARD.encode(encrypted), expires, hash],
        )
        .map_err(|_| AuthError::Unavailable)?;
        audit(&tx, now, "mfa_setup")?;
        tx.commit().map_err(|_| AuthError::Unavailable)?;
        self.stepup_rate.remove(&hash);
        Ok(TotpSetup { secret, expires })
    }

    /// Complete enrollment and issue one-time recovery codes atomically.
    pub fn enable_totp(
        &mut self,
        cookie: &str,
        csrf: &str,
        input: Reauthentication<'_>,
        now: i64,
        monotonic: Duration,
    ) -> Result<Zeroizing<Vec<String>>> {
        Self::validate_confirmation(&input, now)?;
        self.session(cookie, Some(csrf), now)?;
        let hash = digest(cookie);
        reserve_attempt(&mut self.enroll_rate, &hash, monotonic)?;
        reserve_attempt(&mut self.stepup_rate, &hash, monotonic)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| AuthError::Unavailable)?;
        Self::confirm_admin(&tx, &self.key, &input, now)?;
        let (enabled, pending, expires, owner): (i64, String, i64, String) = tx
            .query_row(
                "SELECT enabled,pending,pending_expires,pending_session FROM mfa WHERE id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(|_| AuthError::Unavailable)?;
        if enabled != 0
            || expires < now
            || owner.len() != hash.len()
            || !bool::from(owner.as_bytes().ct_eq(hash.as_bytes()))
        {
            return Err(AuthError::Conflict);
        }
        let pending = STANDARD
            .decode(pending)
            .map_err(|_| AuthError::Unavailable)?;
        let secret = open_xgb1(&pending, self.key.as_ref(), b"xcli:mfa:v1")
            .map_err(|_| AuthError::Unavailable)?;
        let secret = std::str::from_utf8(&secret).map_err(|_| AuthError::Unavailable)?;
        let step = verify_totp(secret, input.code, now, -1)
            .map_err(|_| AuthError::Unavailable)?
            .ok_or(AuthError::InvalidCredentials)?;
        tx.execute("UPDATE mfa SET enabled=1,secret=pending,last_step=?,pending='',pending_expires=0,pending_session='' WHERE id=1", [step]).map_err(|_| AuthError::Unavailable)?;
        tx.execute("DELETE FROM sessions WHERE hash<>?", [&hash])
            .map_err(|_| AuthError::Unavailable)?;
        tx.execute("DELETE FROM mfa_sessions", [])
            .map_err(|_| AuthError::Unavailable)?;
        tx.execute("INSERT INTO mfa_sessions(hash) VALUES(?)", [&hash])
            .map_err(|_| AuthError::Unavailable)?;
        let codes = make_recovery(&tx)?;
        audit(&tx, now, "mfa_enabled")?;
        tx.commit().map_err(|_| AuthError::Unavailable)?;
        self.stepup_rate.remove(&hash);
        self.enroll_rate.remove(&hash);
        Ok(codes)
    }

    pub fn disable_totp(
        &mut self,
        cookie: &str,
        csrf: &str,
        input: Reauthentication<'_>,
        now: i64,
        monotonic: Duration,
    ) -> Result<()> {
        Self::validate_confirmation(&input, now)?;
        self.session(cookie, Some(csrf), now)?;
        let hash = digest(cookie);
        reserve_attempt(&mut self.stepup_rate, &hash, monotonic)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| AuthError::Unavailable)?;
        Self::confirm_admin(&tx, &self.key, &input, now)?;
        tx.execute("UPDATE mfa SET enabled=0,secret='',last_step=-1,pending='',pending_expires=0,pending_session='' WHERE id=1", []).map_err(|_| AuthError::Unavailable)?;
        tx.execute("DELETE FROM recovery_codes", [])
            .map_err(|_| AuthError::Unavailable)?;
        tx.execute("DELETE FROM sessions", [])
            .map_err(|_| AuthError::Unavailable)?;
        tx.execute("DELETE FROM mfa_sessions", [])
            .map_err(|_| AuthError::Unavailable)?;
        audit(&tx, now, "mfa_disabled")?;
        tx.commit().map_err(|_| AuthError::Unavailable)?;
        self.stepup_rate.remove(&hash);
        Ok(())
    }

    pub fn regenerate_recovery(
        &mut self,
        cookie: &str,
        csrf: &str,
        input: Reauthentication<'_>,
        now: i64,
        monotonic: Duration,
    ) -> Result<Zeroizing<Vec<String>>> {
        Self::validate_confirmation(&input, now)?;
        self.session(cookie, Some(csrf), now)?;
        let hash = digest(cookie);
        reserve_attempt(&mut self.stepup_rate, &hash, monotonic)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| AuthError::Unavailable)?;
        let enabled: i64 = tx
            .query_row("SELECT enabled FROM mfa WHERE id=1", [], |row| row.get(0))
            .map_err(|_| AuthError::Unavailable)?;
        if enabled == 0 {
            return Err(AuthError::Conflict);
        }
        Self::confirm_admin(&tx, &self.key, &input, now)?;
        let codes = make_recovery(&tx)?;
        audit(&tx, now, "recovery_regenerated")?;
        tx.commit().map_err(|_| AuthError::Unavailable)?;
        self.stepup_rate.remove(&hash);
        Ok(codes)
    }

    /// Verify the administrator again, update the legacy password hash and
    /// invalidate all sessions in one transaction. The caller must enforce
    /// the trusted origin and serialize this with other state mutations.
    pub fn change_password(
        &mut self,
        cookie: &str,
        csrf: &str,
        input: PasswordChange<'_>,
        now: i64,
        monotonic: Duration,
    ) -> Result<()> {
        let PasswordChange {
            current,
            next,
            code,
        } = input;
        if !(16..=256).contains(&next.chars().count()) {
            return Err(AuthError::InvalidInput);
        }
        let confirmation = Reauthentication {
            password: current,
            code,
        };
        Self::validate_confirmation(&confirmation, now)?;
        self.session(cookie, Some(csrf), now)?;
        let token_hash = digest(cookie);
        reserve_attempt(&mut self.stepup_rate, &token_hash, monotonic)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| AuthError::Unavailable)?;
        Self::confirm_admin(&tx, &self.key, &confirmation, now)?;
        let next_hash = hash_password(next).map_err(|_| AuthError::Unavailable)?;
        tx.execute(
            "UPDATE admin SET password=? WHERE id=1",
            [next_hash.as_str()],
        )
        .map_err(|_| AuthError::Unavailable)?;
        tx.execute("DELETE FROM sessions", [])
            .map_err(|_| AuthError::Unavailable)?;
        audit(&tx, now, "password_changed")?;
        tx.commit().map_err(|_| AuthError::Unavailable)?;
        self.stepup_rate.remove(&token_hash);
        Ok(())
    }
}
