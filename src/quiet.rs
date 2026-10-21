//! Quiet hours: hold non-urgent pushes overnight, then send one digest.
//!
//! Events are always *stored* by the host; quiet hours only decide whether
//! the phone is buzzed now. `crit` (configurable) always breaks through.
//! Times are minutes after local midnight; the host supplies local time, so
//! this module needs no time-zone database.

use crate::{Event, Severity};
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct QuietHours {
    /// "HH:MM", local. A window may wrap midnight (22:30–07:30).
    pub start: String,
    pub end: String,
    /// Events at or above this severity still push during quiet hours.
    #[serde(default = "default_break_through")]
    pub break_through: Severity,
}

fn default_break_through() -> Severity {
    Severity::Crit
}

#[derive(Debug, PartialEq, Eq)]
pub enum Delivery {
    Now,
    Hold,
}

impl QuietHours {
    pub fn parse_hhmm(s: &str) -> Result<u16, String> {
        let (h, m) = s
            .split_once(':')
            .ok_or_else(|| format!("expected HH:MM, got {s:?}"))?;
        let (h, m): (u16, u16) = (
            h.parse().map_err(|_| format!("bad hour in {s:?}"))?,
            m.parse().map_err(|_| format!("bad minute in {s:?}"))?,
        );
        if h > 23 || m > 59 {
            return Err(format!("{s:?} is not a time of day"));
        }
        Ok(h * 60 + m)
    }

    pub fn validate(&self) -> Result<(), String> {
        Self::parse_hhmm(&self.start)?;
        Self::parse_hhmm(&self.end)?;
        Ok(())
    }

    /// Is `minute` (0–1439, local) inside the window?
    pub fn active(&self, minute: u16) -> bool {
        let (Ok(s), Ok(e)) = (Self::parse_hhmm(&self.start), Self::parse_hhmm(&self.end)) else {
            return false;
        };
        if s == e {
            false
        } else if s < e {
            (s..e).contains(&minute)
        } else {
            minute >= s || minute < e
        }
    }

    pub fn delivery(&self, ev: &Event, minute: u16) -> Delivery {
        if self.active(minute) && ev.severity < self.break_through {
            Delivery::Hold
        } else {
            Delivery::Now
        }
    }
}

/// One morning push summarizing what was held overnight.
pub fn digest(held: &[Event]) -> Option<Event> {
    if held.is_empty() {
        return None;
    }
    let worst = held
        .iter()
        .map(|e| e.severity)
        .max()
        .unwrap_or(Severity::Info);
    let mut titles: Vec<&str> = held.iter().map(|e| e.title.as_str()).collect();
    titles.dedup();
    let shown: Vec<&str> = titles.iter().take(8).copied().collect();
    let more = titles.len().saturating_sub(shown.len());
    let mut body = shown.join(" · ");
    if more > 0 {
        body.push_str(&format!(" · +{more} more"));
    }
    Some(Event::new(
        "quiet",
        worst,
        "quiet:digest",
        format!("{} alert(s) during quiet hours", held.len()),
        body,
        String::new(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q() -> QuietHours {
        QuietHours {
            start: "22:30".into(),
            end: "07:30".into(),
            break_through: Severity::Crit,
        }
    }
    fn ev(sev: Severity, title: &str) -> Event {
        Event::new("units", sev, title, title, "", "")
    }

    #[test]
    fn window_wraps_midnight() {
        let q = q();
        assert!(q.active(23 * 60) && q.active(0) && q.active(7 * 60 + 29));
        assert!(!q.active(7 * 60 + 30) && !q.active(12 * 60) && !q.active(22 * 60 + 29));
        let day = QuietHours {
            start: "13:00".into(),
            end: "14:00".into(),
            break_through: Severity::Crit,
        };
        assert!(day.active(13 * 60 + 30) && !day.active(14 * 60));
    }

    #[test]
    fn crit_breaks_through_others_wait() {
        let q = q();
        assert_eq!(q.delivery(&ev(Severity::Warn, "w"), 60), Delivery::Hold);
        assert_eq!(q.delivery(&ev(Severity::Crit, "c"), 60), Delivery::Now);
        assert_eq!(q.delivery(&ev(Severity::Info, "i"), 12 * 60), Delivery::Now);
    }

    #[test]
    fn digest_summarizes_and_takes_worst_severity() {
        assert!(digest(&[]).is_none());
        let held: Vec<Event> = (0..10)
            .map(|i| {
                ev(
                    if i == 3 {
                        Severity::Warn
                    } else {
                        Severity::Info
                    },
                    &format!("t{i}"),
                )
            })
            .collect();
        let d = digest(&held).unwrap();
        assert_eq!(d.severity, Severity::Warn);
        assert_eq!(d.title, "10 alert(s) during quiet hours");
        assert!(d.body.ends_with("+2 more"), "{}", d.body);
    }

    #[test]
    fn bad_times_are_rejected() {
        assert!(QuietHours::parse_hhmm("24:00").is_err());
        assert!(QuietHours::parse_hhmm("7").is_err());
        assert_eq!(QuietHours::parse_hhmm("07:05").unwrap(), 425);
    }
}
