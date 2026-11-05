//! Legacy-compatible user input, status, and transactional storage.
//!
//! This module does not authorize requests or reconcile cores. The eventual
//! service must serialize authenticated mutations with session checks and
//! reconcile them with the local and remote cores before production use.
mod repository;
pub use repository::{AuditEvent, Repository, StoreError, UserSummary};
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, PartialEq, Eq)]
pub enum ValidationError {
    Shape,
    Name,
    Enabled,
    Quota,
    Expires,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct UserInput {
    pub name: String,
    pub enabled: bool,
    pub quota: i64,
    pub expires: i64,
}

// Keep the legacy explicit set: Rust's Unicode whitespace predicate is not
// identical for every code point and must not change existing user names.
fn legacy_space(c: char) -> bool {
    matches!(c as u32, 9..=13 | 0x1c..=0x20 | 0x85 | 0xa0 | 0x1680
        | 0x2000..=0x200a | 0x2028 | 0x2029 | 0x202f | 0x205f | 0x3000)
}

pub fn validate(input: &Value) -> Result<UserInput, ValidationError> {
    let object = input.as_object().ok_or(ValidationError::Shape)?;
    if !object.contains_key("name")
        || object
            .keys()
            .any(|key| !matches!(key.as_str(), "name" | "enabled" | "quota" | "expires"))
    {
        return Err(ValidationError::Shape);
    }
    let name = object["name"].as_str().ok_or(ValidationError::Name)?;
    if !(1..=60).contains(&name.chars().count()) {
        return Err(ValidationError::Name);
    }
    let name = name.trim_matches(legacy_space);
    if name.is_empty() || name.chars().any(|c| (c as u32) < 32) {
        return Err(ValidationError::Name);
    }
    let enabled = match object.get("enabled") {
        Some(value) => value.as_bool().ok_or(ValidationError::Enabled)?,
        None => true,
    };
    fn integer(
        value: Option<&Value>,
        maximum: i64,
        error: ValidationError,
    ) -> Result<i64, ValidationError> {
        match value {
            None => Ok(0),
            Some(value) => value
                .as_i64()
                .filter(|n| (0..=maximum).contains(n))
                .ok_or(error),
        }
    }
    Ok(UserInput {
        name: name.to_owned(),
        enabled,
        quota: integer(
            object.get("quota"),
            10_000_000_000_000_000,
            ValidationError::Quota,
        )?,
        expires: integer(
            object.get("expires"),
            4_102_444_800,
            ValidationError::Expires,
        )?,
    })
}

/// Preserve the legacy precedence and avoid overflowing upload + download.
pub fn status(
    enabled: bool,
    expires: i64,
    quota: i64,
    upload: i64,
    download: i64,
    now: i64,
) -> &'static str {
    if !enabled {
        "disabled"
    } else if expires != 0 && expires <= now {
        "expired"
    } else if quota != 0 && (upload >= quota || download >= quota.saturating_sub(upload)) {
        "exhausted"
    } else {
        "active"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn validation_preserves_legacy_shape_and_unicode_trimming() {
        assert_eq!(
            validate(&json!({"name":"\u{2003} Alice \u{3000}"})).unwrap(),
            UserInput {
                name: "Alice".into(),
                enabled: true,
                quota: 0,
                expires: 0
            }
        );
        assert_eq!(validate(&json!({"name":"  "})), Err(ValidationError::Name));
        assert_eq!(
            validate(&json!({"name":"a\nb"})),
            Err(ValidationError::Name)
        );
        assert_eq!(
            validate(&json!({"name":"a".repeat(61)})),
            Err(ValidationError::Name)
        );
        assert_eq!(
            validate(&json!({"name":"a", "extra":1})),
            Err(ValidationError::Shape)
        );
        assert_eq!(
            validate(&json!({"name":"a", "enabled":1})),
            Err(ValidationError::Enabled)
        );
        assert_eq!(
            validate(&json!({"name":"a", "quota":-1})),
            Err(ValidationError::Quota)
        );
        assert_eq!(
            validate(&json!({"name":"a", "quota":1.0})),
            Err(ValidationError::Quota)
        );
        assert_eq!(
            validate(&json!({"name":"a", "expires":4_102_444_801_i64})),
            Err(ValidationError::Expires)
        );
        assert!(validate(
            &json!({"name":"甲", "quota":10_000_000_000_000_000_i64, "expires":4_102_444_800_i64})
        )
        .is_ok());
    }

    #[test]
    fn status_precedence_and_quota_boundary() {
        assert_eq!(status(false, 1, 1, 1, 1, 2), "disabled");
        assert_eq!(status(true, 1, 1, 1, 1, 2), "expired");
        assert_eq!(status(true, 0, 100, 40, 59, 2), "active");
        assert_eq!(status(true, 0, 100, 40, 60, 2), "exhausted");
        assert_eq!(status(true, 0, 0, i64::MAX, i64::MAX, 2), "active");
    }
}
