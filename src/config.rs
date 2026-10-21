//! Warnflare configuration, normally a `[warnflare]` table (or file) loaded
//! by the host. Everything is optional: an empty config still enables the
//! unit rules, which need no settings.
//!
//! ```toml
//! ignore_units = ["flaky-experiment.service"]
//!
//! [quiet_hours]
//! start = "22:30"
//! end = "07:30"
//! break_through = "crit"
//!
//! [webhook]
//! token_file = "~/.config/nightwatch/warnflare-token"
//!
//! [[freshness]]
//! name = "GitLab backup"
//! path = "~/.local/state/cybercore-gitlab-backup/last.json"
//! json_pointer = "/at"
//! max_age_secs = 46800
//!
//! [[journal]]
//! name = "VortexWall ban"
//! unit = "vortexwall-enforce.service"
//! pattern = "(?i)\\bbanned\\b"
//! severity = "info"
//! ```

use crate::freshness::Freshness;
use crate::journal::{JournalRule, JournalRules};
use crate::quiet::QuietHours;
use serde::Deserialize;

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub ignore_units: Vec<String>,
    #[serde(default)]
    pub quiet_hours: Option<QuietHours>,
    #[serde(default)]
    pub webhook: Option<WebhookConfig>,
    #[serde(default)]
    pub freshness: Vec<Freshness>,
    #[serde(default)]
    pub journal: Vec<JournalRule>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookConfig {
    /// File holding the bearer token (keep it 0600). The token is never
    /// put in the config itself.
    pub token_file: String,
}

impl Config {
    pub fn from_toml(text: &str) -> Result<Config, String> {
        let c: Config = toml::from_str(text).map_err(|e| e.to_string())?;
        c.validate()?;
        Ok(c)
    }

    /// Catch mistakes at startup instead of at 3 a.m.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(q) = &self.quiet_hours {
            q.validate()?;
        }
        let mut names = std::collections::HashSet::new();
        for f in &self.freshness {
            if f.max_age_secs == 0 {
                return Err(format!("freshness {:?}: max_age_secs must be > 0", f.name));
            }
            if !names.insert(("freshness", f.name.as_str())) {
                return Err(format!("duplicate freshness rule {:?}", f.name));
            }
        }
        for j in &self.journal {
            if !names.insert(("journal", j.name.as_str())) {
                return Err(format!("duplicate journal rule {:?}", j.name));
            }
        }
        JournalRules::new(self.journal.clone()).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Severity;

    #[test]
    fn documented_example_parses() {
        let doc = include_str!("config.rs");
        let toml: String = doc
            .lines()
            .skip_while(|l| !l.starts_with("//! ```toml"))
            .skip(1)
            .take_while(|l| !l.starts_with("//! ```"))
            .map(|l| l.trim_start_matches("//!").trim_start_matches(' '))
            .collect::<Vec<_>>()
            .join("\n");
        let c = Config::from_toml(&toml).unwrap();
        assert_eq!(c.freshness[0].json_pointer.as_deref(), Some("/at"));
        assert_eq!(c.journal[0].severity, Severity::Info);
        assert_eq!(c.quiet_hours.unwrap().break_through, Severity::Crit);
    }

    #[test]
    fn empty_config_is_fine() {
        let c = Config::from_toml("").unwrap();
        assert!(c.freshness.is_empty() && c.quiet_hours.is_none());
    }

    #[test]
    fn mistakes_are_caught() {
        for (bad, why) in [
            ("[quiet_hours]\nstart = \"25:00\"\nend = \"07:00\"", "time"),
            (
                "[[freshness]]\nname = \"a\"\npath = \"/x\"\nmax_age_secs = 0",
                "> 0",
            ),
            ("[[journal]]\nname = \"a\"\npattern = \"(\"", "\"a\""),
            (
                "[[journal]]\nname = \"a\"\n[[journal]]\nname = \"a\"",
                "duplicate",
            ),
            ("surprise = 1", "unknown field"),
        ] {
            let e = Config::from_toml(bad).unwrap_err();
            assert!(e.contains(why), "{bad:?} → {e}");
        }
    }
}
