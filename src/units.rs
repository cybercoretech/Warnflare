//! systemd unit rules.
//!
//! [`UnitWatch::observe`] compares successive snapshots (as DaemonHall's
//! `/api/units` reports them) and raises:
//!
//! - **already failed**: a unit is `failed` the first time it's seen;
//! - **failed**: a unit moved into `failed`;
//! - **failed again**: a unit is still `failed`, but a timer that triggers it
//!   has run since the last snapshot, so it ran and failed once more (a
//!   oneshot can do that entirely between two polls);
//! - **restarted**: `NRestarts` went up;
//! - **recovered**: a unit left `failed` with a successful result.

use crate::{short_unit, Event, Severity};
use serde::Deserialize;
use std::collections::HashMap;

/// One unit as the host sees it. Field names match DaemonHall's API, so a
/// host can deserialize `units[]` straight into this.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub struct UnitSnapshot {
    pub id: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub active_state: String,
    #[serde(default)]
    pub result: String,
    #[serde(default)]
    pub n_restarts: u64,
    /// Timers only: when the timer last elapsed (Unix seconds).
    #[serde(default)]
    pub last_run: Option<u64>,
    /// Services: the timers (or other units) that start this one.
    #[serde(default)]
    pub triggered_by: Vec<String>,
}

impl UnitSnapshot {
    fn failed(&self) -> bool {
        self.active_state == "failed"
    }
}

/// Unit ids to never alert on (e.g. units that are expected to fail).
#[derive(Clone, Debug, Default)]
pub struct UnitFilter {
    pub ignore: Vec<String>,
}

impl UnitFilter {
    fn allows(&self, id: &str) -> bool {
        !self.ignore.iter().any(|i| i == id || i == short_unit(id))
    }
}

#[derive(Default)]
pub struct UnitWatch {
    prev: Option<HashMap<String, UnitSnapshot>>,
    filter: UnitFilter,
}

impl UnitWatch {
    pub fn new(filter: UnitFilter) -> UnitWatch {
        UnitWatch { prev: None, filter }
    }

    /// Feed the latest full snapshot; returns the events it implies.
    pub fn observe(&mut self, units: Vec<UnitSnapshot>) -> Vec<Event> {
        let now: HashMap<String, UnitSnapshot> =
            units.into_iter().map(|u| (u.id.clone(), u)).collect();
        let mut out = Vec::new();
        let mut ids: Vec<&String> = now.keys().collect();
        ids.sort(); // deterministic event order

        for id in ids {
            let u = &now[id];
            if !self.filter.allows(id) || u.kind == "timer" {
                continue;
            }
            let name = short_unit(id);
            let was = self.prev.as_ref().and_then(|p| p.get(id));
            match was {
                None if self.prev.is_none() && u.failed() => out.push(failed_event(
                    u,
                    format!("{name} is failed"),
                    format!(
                        "{id} was already in the failed state when watching started (result: {}).",
                        u.result
                    ),
                )),
                None => {}
                Some(w) => {
                    if u.failed() && !w.failed() {
                        out.push(failed_event(
                            u,
                            format!("{name} failed"),
                            format!("{id} entered the failed state (result: {}).", u.result),
                        ));
                    } else if u.failed() && self.timer_ran_since(&now, u) {
                        out.push(failed_event(
                            u,
                            format!("{name} failed again"),
                            format!(
                                "{id} ran again on its timer and is still failed (result: {}).",
                                u.result
                            ),
                        ));
                    } else if w.failed() && !u.failed() && u.result == "success" {
                        out.push(Event::new(
                            "units",
                            Severity::Info,
                            format!("unit-recovered:{id}"),
                            format!("{name} recovered"),
                            format!("{id} is {} again.", u.active_state),
                            id.clone(),
                        ));
                    }
                    if u.n_restarts > w.n_restarts {
                        out.push(Event::new(
                            "units",
                            Severity::Warn,
                            format!("unit-restarted:{id}"),
                            format!("{name} restarted"),
                            format!(
                                "{id} restarted {} time(s) since the last check.",
                                u.n_restarts - w.n_restarts
                            ),
                            id.clone(),
                        ));
                    }
                }
            }
        }
        self.prev = Some(now);
        out
    }

    /// Did any timer that triggers `u` elapse since the previous snapshot?
    fn timer_ran_since(&self, now: &HashMap<String, UnitSnapshot>, u: &UnitSnapshot) -> bool {
        let Some(prev) = &self.prev else { return false };
        u.triggered_by.iter().any(|t| {
            let t = scoped(&u.id, t);
            match (
                now.get(&t).and_then(|x| x.last_run),
                prev.get(&t).and_then(|x| x.last_run),
            ) {
                (Some(n), Some(p)) => n > p,
                (Some(_), None) => true,
                _ => false,
            }
        })
    }
}

/// DaemonHall lists `triggered_by` without the `user:` prefix; resolve it in
/// the same scope as the service it triggers.
fn scoped(service_id: &str, other: &str) -> String {
    match service_id.strip_prefix("user:") {
        Some(_) if !other.starts_with("user:") => format!("user:{other}"),
        _ => other.to_string(),
    }
}

fn failed_event(u: &UnitSnapshot, title: String, body: String) -> Event {
    Event::new(
        "units",
        Severity::Crit,
        format!("unit-failed:{}", u.id),
        title,
        body,
        u.id.clone(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svc(id: &str, state: &str, result: &str, trig: &[&str]) -> UnitSnapshot {
        UnitSnapshot {
            id: id.into(),
            kind: "service".into(),
            active_state: state.into(),
            result: result.into(),
            triggered_by: trig.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }
    fn timer(id: &str, last: u64) -> UnitSnapshot {
        UnitSnapshot {
            id: id.into(),
            kind: "timer".into(),
            active_state: "active".into(),
            last_run: Some(last),
            ..Default::default()
        }
    }

    #[test]
    fn already_failed_at_start_is_reported() {
        let mut w = UnitWatch::default();
        let ev = w.observe(vec![
            svc(
                "sigilward-check.service",
                "failed",
                "exit-code",
                &["sigilward-check.timer"],
            ),
            svc("argus.service", "active", "success", &[]),
        ]);
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].title, "sigilward-check is failed");
        assert_eq!(ev[0].severity, Severity::Crit);
        assert_eq!(ev[0].key, "unit-failed:sigilward-check.service");
    }

    #[test]
    fn oneshot_failing_again_between_polls_is_reported() {
        // The SigilWard case: failed, then its daily timer runs it and it fails again.
        let mut w = UnitWatch::default();
        w.observe(vec![
            svc(
                "sigilward-check.service",
                "failed",
                "exit-code",
                &["sigilward-check.timer"],
            ),
            timer("sigilward-check.timer", 100),
        ]);
        let quiet = w.observe(vec![
            svc(
                "sigilward-check.service",
                "failed",
                "exit-code",
                &["sigilward-check.timer"],
            ),
            timer("sigilward-check.timer", 100),
        ]);
        assert!(quiet.is_empty(), "no new run, no new event");
        let ev = w.observe(vec![
            svc(
                "sigilward-check.service",
                "failed",
                "exit-code",
                &["sigilward-check.timer"],
            ),
            timer("sigilward-check.timer", 86_500),
        ]);
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].title, "sigilward-check failed again");
        assert_eq!(
            ev[0].key, "unit-failed:sigilward-check.service",
            "same key, so the host folds it"
        );
    }

    #[test]
    fn user_scope_triggers_resolve() {
        let mut w = UnitWatch::default();
        let s = |st| {
            svc(
                "user:cybercore-gitlab-backup.service",
                st,
                "exit-code",
                &["cybercore-gitlab-backup.timer"],
            )
        };
        w.observe(vec![
            s("failed"),
            timer("user:cybercore-gitlab-backup.timer", 10),
        ]);
        let ev = w.observe(vec![
            s("failed"),
            timer("user:cybercore-gitlab-backup.timer", 20),
        ]);
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].title, "cybercore-gitlab-backup failed again");
    }

    #[test]
    fn transition_restart_and_recovery() {
        let mut w = UnitWatch::default();
        assert!(w
            .observe(vec![svc("holodrive.service", "active", "success", &[])])
            .is_empty());
        let ev = w.observe(vec![svc("holodrive.service", "failed", "signal", &[])]);
        assert_eq!(ev[0].title, "holodrive failed");
        let mut back = svc("holodrive.service", "active", "success", &[]);
        back.n_restarts = 2;
        let ev = w.observe(vec![back]);
        let titles: Vec<_> = ev.iter().map(|e| e.title.as_str()).collect();
        assert_eq!(titles, ["holodrive recovered", "holodrive restarted"]);
        assert_eq!(ev[0].severity, Severity::Info);
    }

    #[test]
    fn ignored_units_stay_quiet() {
        let mut w = UnitWatch::new(UnitFilter {
            ignore: vec!["flaky".into()],
        });
        assert!(w
            .observe(vec![svc("flaky.service", "failed", "exit-code", &[])])
            .is_empty());
    }

    #[test]
    fn deserializes_daemonhall_unit_json() {
        let u: UnitSnapshot = serde_json::from_str(
            r#"{"id":"user:x.service","kind":"service","active_state":"failed","result":"exit-code","n_restarts":0,"last_run":null,"triggered_by":["x.timer"],"extra":1}"#,
        ).unwrap();
        assert!(u.failed());
        assert_eq!(u.triggered_by, ["x.timer"]);
    }
}
