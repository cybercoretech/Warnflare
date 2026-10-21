//! Webhook events: let scripts, backups (Gravevault) and CI raise alerts.
//!
//! The host exposes an HTTP endpoint (loopback or tailnet) and passes the
//! bearer token and raw body here. Validation is strict: the body is size
//! capped, every field is bounded, keys use a safe character set, and the
//! token comparison is constant-time.

use crate::{Event, Severity};
use serde::Deserialize;

pub const MAX_BODY_BYTES: usize = 16 * 1024;
const MAX_TITLE: usize = 120;
const MAX_TEXT: usize = 4 * 1024;
const MAX_KEY: usize = 96;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Incoming {
    /// Who is reporting, e.g. `gravevault`. Prefixes the key.
    source: String,
    severity: Severity,
    /// Stable id of the condition, so repeats fold into one alert.
    key: String,
    title: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    subject: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Rejected {
    /// 401: missing or wrong token.
    Unauthorized,
    /// 413: body over [`MAX_BODY_BYTES`].
    TooLarge,
    /// 400: not valid JSON for the schema, or a field out of bounds.
    Invalid(String),
}

/// Check the token and turn a request body into an [`Event`].
pub fn accept(
    expected_token: &str,
    presented_token: Option<&str>,
    body: &[u8],
) -> Result<Event, Rejected> {
    match presented_token {
        Some(t)
            if !expected_token.is_empty()
                && constant_time_eq(t.as_bytes(), expected_token.as_bytes()) => {}
        _ => return Err(Rejected::Unauthorized),
    }
    if body.len() > MAX_BODY_BYTES {
        return Err(Rejected::TooLarge);
    }
    let i: Incoming = serde_json::from_slice(body).map_err(|e| Rejected::Invalid(e.to_string()))?;
    let ident = |name: &str, v: &str| {
        if v.is_empty()
            || v.len() > MAX_KEY
            || !v
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.:/".contains(&b))
        {
            Err(Rejected::Invalid(format!(
                "{name} must be 1–{MAX_KEY} chars of [A-Za-z0-9-_.:/]"
            )))
        } else {
            Ok(())
        }
    };
    ident("source", &i.source)?;
    ident("key", &i.key)?;
    if i.title.trim().is_empty()
        || i.title.chars().count() > MAX_TITLE
        || i.title.chars().any(char::is_control)
    {
        return Err(Rejected::Invalid(format!(
            "title must be 1–{MAX_TITLE} printable chars"
        )));
    }
    if i.body.len() > MAX_TEXT || i.subject.len() > MAX_TEXT {
        return Err(Rejected::Invalid(format!(
            "body and subject are limited to {MAX_TEXT} bytes"
        )));
    }
    Ok(Event {
        source: "webhook".into(),
        severity: i.severity,
        key: format!("hook:{}:{}", i.source, i.key),
        title: i.title,
        body: i.body,
        subject: if i.subject.is_empty() {
            i.source
        } else {
            i.subject
        },
    })
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    // Length isn't secret (tokens have a fixed format); the contents are.
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "wf_0123456789abcdef";

    #[test]
    fn accepts_a_valid_event() {
        let ev = accept(TOKEN, Some(TOKEN), br#"{"source":"gravevault","severity":"crit","key":"restore-drill","title":"Restore drill failed","body":"vault snapshot 42 did not verify"}"#).unwrap();
        assert_eq!(ev.key, "hook:gravevault:restore-drill");
        assert_eq!(ev.severity, Severity::Crit);
        assert_eq!(ev.subject, "gravevault");
    }

    #[test]
    fn rejects_bad_tokens() {
        let body = br#"{"source":"x","severity":"info","key":"k","title":"t"}"#;
        assert_eq!(accept(TOKEN, None, body), Err(Rejected::Unauthorized));
        assert_eq!(
            accept(TOKEN, Some("wf_0123456789abcdeX"), body),
            Err(Rejected::Unauthorized)
        );
        assert_eq!(
            accept("", Some(""), body),
            Err(Rejected::Unauthorized),
            "an empty configured token never matches"
        );
    }

    #[test]
    fn rejects_oversized_and_malformed_bodies() {
        let big = vec![b' '; MAX_BODY_BYTES + 1];
        assert_eq!(accept(TOKEN, Some(TOKEN), &big), Err(Rejected::TooLarge));
        for bad in [
            &br#"{"source":"x","severity":"loud","key":"k","title":"t"}"#[..],
            br#"{"source":"x y","severity":"info","key":"k","title":"t"}"#,
            br#"{"source":"x","severity":"info","key":"","title":"t"}"#,
            br#"{"source":"x","severity":"info","key":"k","title":"  "}"#,
            br#"{"source":"x","severity":"info","key":"k","title":"t","extra":1}"#,
            b"not json",
        ] {
            assert!(
                matches!(accept(TOKEN, Some(TOKEN), bad), Err(Rejected::Invalid(_))),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }
}
