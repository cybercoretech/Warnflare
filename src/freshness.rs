//! Freshness rules: "this should have happened recently".
//!
//! A job can stop running without ever failing: a disabled timer, a machine
//! that slept through every slot, a script that exits before doing its work.
//! A freshness rule watches the evidence the job leaves behind: a file's
//! modification time, or a timestamp inside a JSON state file (e.g. the GitLab
//! backup's `last.json` `"at"` field).

use crate::{Event, Severity};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Deserialize)]
pub struct Freshness {
    /// Shown in the alert, e.g. "GitLab backup".
    pub name: String,
    /// File to check. `~/` is expanded.
    pub path: String,
    /// JSON pointer (RFC 6901) to a timestamp inside the file, e.g. `/at`.
    /// Accepts Unix seconds or an RFC 3339 UTC string (`2026-10-21T13:26:39Z`).
    /// Without it, the file's modification time is used.
    #[serde(default)]
    pub json_pointer: Option<String>,
    /// How old the evidence may get, in seconds.
    pub max_age_secs: u64,
    #[serde(default = "default_severity")]
    pub severity: Severity,
}

fn default_severity() -> Severity {
    Severity::Warn
}

/// Tracks whether each rule is currently stale, so a stale condition is
/// raised once and its recovery once, instead of every poll.
#[derive(Default)]
pub struct FreshnessWatch {
    stale: std::collections::HashSet<String>,
}

impl FreshnessWatch {
    pub fn check(&mut self, rules: &[Freshness], now: SystemTime, home: &Path) -> Vec<Event> {
        let mut out = Vec::new();
        for r in rules {
            let key = format!("stale:{}", r.name);
            let path = expand(&r.path, home);
            match evidence_time(&path, r.json_pointer.as_deref()) {
                Ok(at) => {
                    let age = now.duration_since(at).unwrap_or(Duration::ZERO);
                    if age.as_secs() > r.max_age_secs {
                        if self.stale.insert(r.name.clone()) {
                            out.push(Event::new(
                                "freshness",
                                r.severity,
                                key,
                                format!("{} is overdue", r.name),
                                format!(
                                    "Last evidence is {} old (limit {}). Checked {}.",
                                    human(age.as_secs()),
                                    human(r.max_age_secs),
                                    path.display()
                                ),
                                path.display().to_string(),
                            ));
                        }
                    } else if self.stale.remove(&r.name) {
                        out.push(Event::new(
                            "freshness",
                            Severity::Info,
                            format!("fresh:{}", r.name),
                            format!("{} is running again", r.name),
                            format!("Last evidence is {} old.", human(age.as_secs())),
                            path.display().to_string(),
                        ));
                    }
                }
                Err(why) => {
                    if self.stale.insert(r.name.clone()) {
                        out.push(Event::new(
                            "freshness",
                            r.severity,
                            key,
                            format!("{} has no evidence", r.name),
                            format!("{}: {why}", path.display()),
                            path.display().to_string(),
                        ));
                    }
                }
            }
        }
        out
    }
}

fn expand(p: &str, home: &Path) -> PathBuf {
    match p.strip_prefix("~/") {
        Some(rest) => home.join(rest),
        None => PathBuf::from(p),
    }
}

fn evidence_time(path: &Path, pointer: Option<&str>) -> Result<SystemTime, String> {
    match pointer {
        None => std::fs::metadata(path)
            .and_then(|m| m.modified())
            .map_err(|e| e.to_string()),
        Some(ptr) => {
            let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
            let v: serde_json::Value =
                serde_json::from_str(&text).map_err(|e| format!("not JSON: {e}"))?;
            let field = v.pointer(ptr).ok_or_else(|| format!("no field at {ptr}"))?;
            if let Some(secs) = field.as_u64() {
                return Ok(UNIX_EPOCH + Duration::from_secs(secs));
            }
            let s = field
                .as_str()
                .ok_or_else(|| format!("{ptr} is neither a number nor a string"))?;
            parse_rfc3339_utc(s).map(|secs| UNIX_EPOCH + Duration::from_secs(secs))
        }
    }
}

/// `YYYY-MM-DDTHH:MM:SS[.frac]Z` → Unix seconds. Only UTC (`Z`) is accepted;
/// state files written by our own tools use it, and refusing offsets keeps
/// this dependency-free and unambiguous.
pub fn parse_rfc3339_utc(s: &str) -> Result<u64, String> {
    let bad = || format!("not an RFC 3339 UTC timestamp: {s}");
    let s = s.strip_suffix('Z').ok_or_else(bad)?;
    let (date, time) = s.split_once('T').ok_or_else(bad)?;
    let time = time.split('.').next().unwrap_or(time);
    let d: Vec<i64> = date
        .split('-')
        .map(|x| x.parse().map_err(|_| bad()))
        .collect::<Result<_, _>>()?;
    let t: Vec<i64> = time
        .split(':')
        .map(|x| x.parse().map_err(|_| bad()))
        .collect::<Result<_, _>>()?;
    if d.len() != 3
        || t.len() != 3
        || !(1..=12).contains(&d[1])
        || !(1..=31).contains(&d[2])
        || t[0] > 23
        || t[1] > 59
        || t[2] > 60
    {
        return Err(bad());
    }
    // Days from the civil date (Howard Hinnant's algorithm).
    let (y, m, day) = (d[0] - i64::from(d[1] <= 2), d[1], d[2]);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + t[0] * 3600 + t[1] * 60 + t[2];
    u64::try_from(secs).map_err(|_| bad())
}

fn human(secs: u64) -> String {
    match secs {
        s if s < 120 => format!("{s} s"),
        s if s < 7200 => format!("{} min", s / 60),
        s if s < 172_800 => format!("{} h", s / 3600),
        s => format!("{} days", s / 86_400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(path: &Path, ptr: Option<&str>, max: u64) -> Freshness {
        Freshness {
            name: "GitLab backup".into(),
            path: path.display().to_string(),
            json_pointer: ptr.map(Into::into),
            max_age_secs: max,
            severity: Severity::Warn,
        }
    }

    #[test]
    fn parses_utc_timestamps() {
        assert_eq!(parse_rfc3339_utc("1970-01-01T00:00:00Z").unwrap(), 0);
        assert_eq!(
            parse_rfc3339_utc("2026-10-21T13:26:39Z").unwrap(),
            1_792_589_199
        );
        assert_eq!(
            parse_rfc3339_utc("2000-02-29T12:00:00.5Z").unwrap(),
            951_825_600
        );
        assert!(parse_rfc3339_utc("2026-10-21T13:26:39+02:00").is_err());
        assert!(parse_rfc3339_utc("yesterday").is_err());
    }

    #[test]
    fn stale_json_field_alerts_once_then_recovers() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("last.json");
        std::fs::write(&f, r#"{"at":"2026-10-21T13:26:39Z","ok":56}"#).unwrap();
        let at = UNIX_EPOCH + Duration::from_secs(1_792_589_199);
        let r = [rule(&f, Some("/at"), 13 * 3600)];
        let mut w = FreshnessWatch::default();
        assert!(w
            .check(&r, at + Duration::from_secs(3600), dir.path())
            .is_empty());
        let late = at + Duration::from_secs(20 * 3600);
        let ev = w.check(&r, late, dir.path());
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].title, "GitLab backup is overdue");
        assert!(ev[0].body.contains("20 h"), "{}", ev[0].body);
        assert!(
            w.check(&r, late, dir.path()).is_empty(),
            "raised once, not every poll"
        );
        std::fs::write(&f, r#"{"at":"2026-10-22T09:00:00Z"}"#).unwrap();
        let ev = w.check(&r, late, dir.path());
        assert_eq!(ev[0].title, "GitLab backup is running again");
        assert_eq!(ev[0].severity, Severity::Info);
    }

    #[test]
    fn missing_file_or_field_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = FreshnessWatch::default();
        let ev = w.check(
            &[rule(&dir.path().join("nope.json"), Some("/at"), 60)],
            SystemTime::now(),
            dir.path(),
        );
        assert_eq!(ev[0].title, "GitLab backup has no evidence");
        let f = dir.path().join("x.json");
        std::fs::write(&f, "{}").unwrap();
        let mut w = FreshnessWatch::default();
        let ev = w.check(&[rule(&f, Some("/at"), 60)], SystemTime::now(), dir.path());
        assert!(ev[0].body.contains("no field at /at"));
    }

    #[test]
    fn mtime_and_home_expansion() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("heartbeat"), "x").unwrap();
        let r = Freshness {
            name: "hb".into(),
            path: "~/heartbeat".into(),
            json_pointer: None,
            max_age_secs: 3600,
            severity: Severity::Info,
        };
        let mut w = FreshnessWatch::default();
        assert!(w
            .check(std::slice::from_ref(&r), SystemTime::now(), dir.path())
            .is_empty());
        let ev = w.check(
            &[r],
            SystemTime::now() + Duration::from_secs(7200),
            dir.path(),
        );
        assert_eq!(ev[0].severity, Severity::Info);
    }
}
