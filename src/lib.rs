//! Warnflare: alert rules for self-hosted machines.
//!
//! The crate is pure decision logic. A host program (nightwatchd) collects the
//! inputs (unit snapshots, journal records, webhook bodies, the clock) and
//! feeds them in; Warnflare answers with [`Event`]s, which the host stores,
//! folds by [`Event::key`] and delivers. Nothing here does I/O except reading
//! the files a [`freshness::Freshness`] rule points at.
//!
//! The rules exist because "alert on a transition into `failed`" misses the
//! cases that matter most: a unit that was already failed when the watcher
//! started, and a timer-driven oneshot that fails again between two polls.
//! A file-integrity check sat red for 18 days that way.

pub mod config;
pub mod freshness;
pub mod journal;
pub mod quiet;
pub mod units;
pub mod webhook;

use serde::{Deserialize, Serialize};

/// How loud an event is. Ordered: `Info < Warn < Crit`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warn,
    Crit,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warn => "warn",
            Severity::Crit => "crit",
        }
    }
}

/// Something worth telling a human about.
///
/// `key` identifies the condition, not the occurrence: the host folds a
/// repeat of an unacknowledged key into the existing alert instead of
/// notifying again, so "failed again" can reuse the "failed" key safely.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Which rule family produced it: `units`, `freshness`, `journal`, `webhook`, `quiet`.
    pub source: String,
    pub severity: Severity,
    pub key: String,
    pub title: String,
    pub body: String,
    /// The thing the event is about (a unit id, a path, a rule name), for linking.
    pub subject: String,
}

impl Event {
    pub fn new(
        source: &str,
        severity: Severity,
        key: impl Into<String>,
        title: impl Into<String>,
        body: impl Into<String>,
        subject: impl Into<String>,
    ) -> Event {
        Event {
            source: source.into(),
            severity,
            key: key.into(),
            title: title.into(),
            body: body.into(),
            subject: subject.into(),
        }
    }
}

/// Unit ids carry a `user:` prefix for user-manager units; titles read better without it.
pub(crate) fn short_unit(id: &str) -> &str {
    let id = id.strip_prefix("user:").unwrap_or(id);
    id.strip_suffix(".service").unwrap_or(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_and_serializes_lowercase() {
        assert!(Severity::Info < Severity::Warn && Severity::Warn < Severity::Crit);
        assert_eq!(serde_json::to_string(&Severity::Crit).unwrap(), "\"crit\"");
        assert_eq!(
            serde_json::from_str::<Severity>("\"warn\"").unwrap(),
            Severity::Warn
        );
    }

    #[test]
    fn short_unit_strips_scope_and_suffix() {
        assert_eq!(short_unit("user:holodrive.service"), "holodrive");
        assert_eq!(short_unit("sigilward-check.service"), "sigilward-check");
        assert_eq!(short_unit("argus.timer"), "argus.timer");
    }
}
