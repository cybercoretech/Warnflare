//! Journal rules: raise an event when a log line matches.
//!
//! The host follows `journalctl -f -o json` (system and/or user) and hands
//! each record to [`JournalRules::check`]. A rule can narrow by unit, by
//! priority (syslog levels: 0 emerg … 3 err … 4 warning … 6 info) and by a
//! regex over `MESSAGE`.

use crate::{short_unit, Event, Severity};
use regex::Regex;
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct JournalRule {
    pub name: String,
    /// Match `_SYSTEMD_UNIT` / `_SYSTEMD_USER_UNIT` exactly (e.g. `vortexwall-enforce.service`).
    #[serde(default)]
    pub unit: Option<String>,
    /// Only records at this priority or more severe (lower number).
    #[serde(default)]
    pub max_priority: Option<u8>,
    /// Regex over the message. Omit to match every record the other filters let through.
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default = "default_severity")]
    pub severity: Severity,
}

fn default_severity() -> Severity {
    Severity::Warn
}

pub struct JournalRules {
    rules: Vec<(JournalRule, Option<Regex>)>,
}

impl JournalRules {
    /// Compile the rules; a bad regex is a configuration error, reported up front.
    pub fn new(rules: Vec<JournalRule>) -> Result<JournalRules, String> {
        let rules = rules
            .into_iter()
            .map(|r| {
                let re = match &r.pattern {
                    Some(p) => {
                        Some(Regex::new(p).map_err(|e| format!("journal rule {:?}: {e}", r.name))?)
                    }
                    None => None,
                };
                Ok((r, re))
            })
            .collect::<Result<_, String>>()?;
        Ok(JournalRules { rules })
    }

    /// One `journalctl -o json` record → the events it triggers.
    pub fn check(&self, record: &serde_json::Value) -> Vec<Event> {
        let field = |k: &str| record.get(k).and_then(|v| v.as_str());
        let message = field("MESSAGE").unwrap_or("");
        let unit = field("_SYSTEMD_USER_UNIT")
            .or_else(|| field("_SYSTEMD_UNIT"))
            .unwrap_or("");
        let priority: Option<u8> = field("PRIORITY").and_then(|p| p.parse().ok());
        let mut out = Vec::new();
        for (r, re) in &self.rules {
            if r.unit.as_deref().is_some_and(|u| u != unit) {
                continue;
            }
            if let Some(max) = r.max_priority {
                if priority.map_or(true, |p| p > max) {
                    continue;
                }
            }
            if re.as_ref().is_some_and(|re| !re.is_match(message)) {
                continue;
            }
            let who = if unit.is_empty() {
                String::from("journal")
            } else {
                short_unit(unit).to_string()
            };
            out.push(Event::new(
                "journal",
                r.severity,
                format!("journal:{}", r.name),
                format!("{}: {}", r.name, who),
                truncate(message, 500),
                unit.to_string(),
            ));
        }
        out
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rules() -> JournalRules {
        JournalRules::new(vec![
            JournalRule {
                name: "VortexWall ban".into(),
                unit: Some("vortexwall-enforce.service".into()),
                max_priority: None,
                pattern: Some(r"(?i)\bbanned\b".into()),
                severity: Severity::Warn,
            },
            JournalRule {
                name: "Kernel errors".into(),
                unit: None,
                max_priority: Some(3),
                pattern: None,
                severity: Severity::Crit,
            },
        ])
        .unwrap()
    }

    #[test]
    fn unit_and_pattern_must_both_match() {
        let r = rules();
        let ev = r.check(&json!({"_SYSTEMD_UNIT":"vortexwall-enforce.service","MESSAGE":"Banned 203.0.113.9 for 24h","PRIORITY":"6"}));
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].title, "VortexWall ban: vortexwall-enforce");
        assert!(r
            .check(&json!({"_SYSTEMD_UNIT":"argus.service","MESSAGE":"banned","PRIORITY":"6"}))
            .is_empty());
    }

    #[test]
    fn priority_threshold() {
        let r = rules();
        let err = r.check(&json!({"MESSAGE":"EXT4-fs error","PRIORITY":"3"}));
        assert_eq!(err.len(), 1);
        assert_eq!(err[0].severity, Severity::Crit);
        assert_eq!(err[0].title, "Kernel errors: journal");
        assert!(r
            .check(&json!({"MESSAGE":"just a warning","PRIORITY":"4"}))
            .is_empty());
        assert!(r.check(&json!({"MESSAGE":"no priority"})).is_empty());
    }

    #[test]
    fn user_unit_field_wins_and_long_messages_truncate() {
        let r = JournalRules::new(vec![JournalRule {
            name: "x".into(),
            unit: Some("holodrive.service".into()),
            max_priority: None,
            pattern: None,
            severity: Severity::Info,
        }])
        .unwrap();
        let long = "é".repeat(400);
        let ev = r.check(&json!({"_SYSTEMD_UNIT":"user@1000.service","_SYSTEMD_USER_UNIT":"holodrive.service","MESSAGE":long}));
        assert_eq!(ev.len(), 1);
        assert!(ev[0].body.ends_with('…') && ev[0].body.len() <= 504);
    }

    #[test]
    fn bad_regex_is_a_config_error() {
        let e = JournalRules::new(vec![JournalRule {
            name: "bad".into(),
            unit: None,
            max_priority: None,
            pattern: Some("(".into()),
            severity: Severity::Info,
        }]);
        assert!(e.err().unwrap().contains("bad"));
    }
}
