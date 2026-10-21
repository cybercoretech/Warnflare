# 🔥 Warnflare

**Alert rules for self-hosted machines: the failures that slip through "alert on change".**

Warnflare is the rules engine inside [nightwatchd](https://github.com/cybercoretech/nightwatchd), the gateway behind the Nightwatch phone app. It's a pure-logic Rust crate: nightwatchd collects the inputs, Warnflare decides what's worth an alert, and nightwatchd stores, folds and pushes them to your phone.

> 🧯 **Why it exists:** a daily integrity check failed every night for **18 days** and nobody was told. The watcher only alerted on a *transition* into `failed`. The unit was already failed when the watcher started, and the timer re-ran it and it failed again between two polls, so no transition was ever seen.

## 🚨 Rules

| | Rule | Catches |
|---|---|---|
| 🧱 | **Units** (`units`) | Already failed when watching starts · newly failed · **failed again** (its timer ran since the last poll, still failed) · restarted · recovered |
| ⏳ | **Freshness** (`freshness`) | A job that stopped without failing: a file's mtime, or a timestamp inside a JSON state file (e.g. `last.json` → `/at`), older than its limit. Raised once, plus one "running again". |
| 📜 | **Journal** (`journal`) | `journalctl -o json` records by unit, priority and regex |
| 🪝 | **Webhook** (`webhook`) | Scripts, backups and CI raise their own alerts: bearer token (constant-time compare), 16 KiB cap, strict schema |
| 🌙 | **Quiet hours** (`quiet`) | Hold non-urgent pushes overnight (`crit` breaks through), then send one morning digest |

Every rule returns `Event { source, severity, key, title, body, subject }`. The **key** names the condition, not the occurrence, so the host folds repeats into one alert instead of buzzing again.

## ⚙️ Configuration

```toml
ignore_units = ["flaky-experiment.service"]

[quiet_hours]
start = "22:30"
end = "07:30"
break_through = "crit"

[webhook]
token_file = "~/.config/nightwatch/warnflare-token"

[[freshness]]
name = "GitLab backup"
path = "~/.local/state/cybercore-gitlab-backup/last.json"
json_pointer = "/at"
max_age_secs = 46800

[[journal]]
name = "VortexWall ban"
unit = "vortexwall-enforce.service"
pattern = "(?i)\\bbanned\\b"
severity = "info"
```

`Config::from_toml` validates everything at startup: times, regexes, duplicate names, unknown keys.

## 🧪 Development

```sh
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

Tests include the exact SigilWard scenario: a timer-driven oneshot failing again between polls.

## 🗺️ Roadmap

- **0.1:** the rules above, embedded in nightwatchd.
- **Next:** rate-limited escalation (re-push an unacked `crit` after N hours); per-rule quiet-hour overrides; a `warnflare check` CLI to dry-run a config against the live machine.

MIT licensed.
