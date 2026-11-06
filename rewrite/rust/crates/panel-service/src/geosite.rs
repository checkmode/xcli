//! Convert the upstream Mihomo classical domain lists for Shadowrocket.
use axum::extract::Path;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

const SOURCE: &str =
    "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical";
const MAX_BYTES: usize = 8 * 1024 * 1024;
type Cache = BTreeMap<String, (Instant, Arc<str>)>;
static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();
static FETCHES: OnceLock<tokio::sync::Semaphore> = OnceLock::new();

fn category(file: &str) -> Option<&str> {
    let name = file.strip_suffix(".list")?;
    (!name.is_empty()
        && name.len() <= 80
        && name.bytes().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'-' | b'_' | b'!' | b'@')
        }))
    .then_some(name)
}

fn convert(source: &str) -> Option<String> {
    let mut output = String::from("# Converted from MetaCubeX/meta-rules-dat (GPL-3.0); unsupported regex entries omitted.\n# Source: https://github.com/MetaCubeX/meta-rules-dat\n");
    let mut count = 0;
    for line in source.lines() {
        let Some((kind, value)) = line.trim().split_once(',') else {
            continue;
        };
        if !matches!(kind, "DOMAIN" | "DOMAIN-SUFFIX" | "DOMAIN-KEYWORD")
            || value.is_empty()
            || value.len() > 253
            || !value
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_'))
        {
            continue;
        }
        output.push_str(kind);
        output.push(',');
        output.push_str(value);
        output.push('\n');
        count += 1;
        if output.len() > MAX_BYTES {
            return None;
        }
    }
    (count > 0).then_some(output)
}

pub async fn rules(Path(file): Path<String>) -> Response {
    let Some(name) = category(&file) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let cache = CACHE.get_or_init(|| Mutex::new(BTreeMap::new()));
    let cached = cache
        .lock()
        .ok()
        .and_then(|values| values.get(name).cloned());
    if let Some((stamp, text)) = &cached {
        if stamp.elapsed() < Duration::from_secs(24 * 3600) {
            return (
                [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                text.to_string(),
            )
                .into_response();
        }
    }
    let Ok(_permit) = FETCHES
        .get_or_init(|| tokio::sync::Semaphore::new(4))
        .try_acquire()
    else {
        return cached.map_or_else(
            || StatusCode::SERVICE_UNAVAILABLE.into_response(),
            |(_, text)| {
                (
                    [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                    text.to_string(),
                )
                    .into_response()
            },
        );
    };
    let fetched = async {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(12))
            .build()
            .ok()?;
        let response = client
            .get(format!("{SOURCE}/{name}.list"))
            .send()
            .await
            .ok()?
            .error_for_status()
            .ok()?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_BYTES as u64)
        {
            return None;
        }
        let bytes = response.bytes().await.ok()?;
        if bytes.len() > MAX_BYTES {
            return None;
        }
        let text = std::str::from_utf8(&bytes).ok()?;
        convert(text)
    }
    .await;
    if let Some(text) = fetched {
        let shared: Arc<str> = Arc::from(text);
        if let Ok(mut values) = cache.lock() {
            if values.len() >= 8 && !values.contains_key(name) {
                if let Some(oldest) = values
                    .iter()
                    .min_by_key(|(_, (stamp, _))| *stamp)
                    .map(|(key, _)| key.clone())
                {
                    values.remove(&oldest);
                }
            }
            values.insert(name.into(), (Instant::now(), shared.clone()));
        }
        return (
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            shared.to_string(),
        )
            .into_response();
    }
    if let Some((_, text)) = cached {
        return (
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            text.to_string(),
        )
            .into_response();
    }
    StatusCode::BAD_GATEWAY.into_response()
}

#[cfg(test)]
mod tests {
    use super::{category, convert};
    #[test]
    fn converts_supported_domains_and_excludes_regex_or_invalid_lines() {
        let result = convert("DOMAIN,example.com\nDOMAIN-SUFFIX,example.net\nDOMAIN-KEYWORD,video\nDOMAIN-REGEX,^test.*\nDOMAIN,bad/path\n").unwrap();
        assert!(result.contains("DOMAIN,example.com\n"));
        assert!(result.contains("DOMAIN-SUFFIX,example.net\n"));
        assert!(result.contains("DOMAIN-KEYWORD,video\n"));
        assert!(!result.contains("DOMAIN-REGEX"));
        assert!(!result.contains("bad/path"));
        assert!(category("geolocation-!cn.list").is_some());
        assert!(category("../cn.list").is_none());
    }
}
