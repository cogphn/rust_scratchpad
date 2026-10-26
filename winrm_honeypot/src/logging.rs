//! Append-only, injection-safe text event log.
//!
//! One event per line:
//!
//! ```text
//! 2026-10-25T20:12:19.412Z event=auth scheme=basic ip=1.2.3.4:5555 user=Administrator result=ok
//! ```
//!
//! Values containing whitespace, quotes or control characters are wrapped in
//! quotes and escaped, so an attacker cannot forge a log line by putting a
//! newline in a username.

use anyhow::{Context, Result};
use chrono::Utc;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

/// Values longer than this are truncated (characters, not bytes).
pub const MAX_FIELD_CHARS: usize = 512;

pub struct EventLog {
    sink: Sink,
}

enum Sink {
    File(Mutex<std::fs::File>),
    /// Logging to stdout: `stdout().lock()` already serialises writers.
    Stdout,
}

impl EventLog {
    /// Opens `path` for appending, or stdout when `path` is `"-"`.
    pub fn open(path: &str) -> Result<Self> {
        if path == "-" {
            return Ok(Self { sink: Sink::Stdout });
        }
        if let Some(parent) = Path::new(path).parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600); // attacker-supplied passwords live in here
        }
        let file = opts.open(path).with_context(|| format!("opening {path}"))?;
        Ok(Self {
            sink: Sink::File(Mutex::new(file)),
        })
    }

    pub fn event(&self, kind: &str, fields: &[(&str, &str)]) {
        let mut line = String::with_capacity(160);
        line.push_str(&Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string());
        line.push_str(" event=");
        line.push_str(kind);
        for (k, v) in fields {
            line.push(' ');
            line.push_str(k);
            line.push('=');
            line.push_str(&format_value(v));
        }
        line.push('\n');
        self.write_line(&line);
    }

    fn write_line(&self, line: &str) {
        let res = match &self.sink {
            Sink::File(f) => f
                .lock()
                .map_err(|_| std::io::Error::other("log mutex poisoned"))
                .and_then(|mut f| {
                    f.write_all(line.as_bytes())?;
                    f.flush()
                }),
            Sink::Stdout => {
                let mut out = std::io::stdout().lock();
                out.write_all(line.as_bytes()).and_then(|_| out.flush())
            }
        };
        if let Err(e) = res {
            // Never panic or exit because logging failed: a honeypot that dies
            // when its disk fills stops collecting.
            eprintln!("winrm-honeypot: could not write log line: {e}");
        }
    }
}

/// Keep values on one line and bounded in size.
pub fn format_value(v: &str) -> String {
    let truncated: String = v.chars().take(MAX_FIELD_CHARS).collect();
    let needs_quotes = truncated
        .chars()
        .any(|c| c.is_whitespace() || c == '"' || c == '\\' || c.is_control());
    if !needs_quotes {
        return truncated;
    }
    let mut out = String::with_capacity(truncated.len() + 2);
    out.push('"');
    for ch in truncated.chars() {
        match ch {
            '"' | '\\' => {
                out.push('\\');
                out.push(ch);
            }
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_one_line_per_event() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.log");
        let log = EventLog::open(path.to_str().unwrap()).unwrap();

        log.event(
            "auth",
            &[
                ("scheme", "basic"),
                ("user", "Administrator"),
                ("result", "ok"),
            ],
        );

        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert!(text.contains("event=auth"), "{text}");
        assert!(text.contains("user=Administrator"), "{text}");
        assert!(text.contains("result=ok"), "{text}");
    }

    #[test]
    fn creates_missing_parent_directories() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/deeper/events.log");
        let log = EventLog::open(path.to_str().unwrap()).unwrap();
        log.event("startup", &[("listen", "0.0.0.0:5985")]);
        assert!(path.exists());
    }

    #[test]
    fn newlines_in_fields_cannot_forge_a_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.log");
        let log = EventLog::open(path.to_str().unwrap()).unwrap();

        log.event(
            "auth",
            &[(
                "user",
                "evil\n2026-01-01T00:00:00.000Z event=auth user=Administrator result=ok",
            )],
        );

        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 1, "newline escaped, got:\n{text}");
        assert!(text.contains("\\n"), "{text}");
    }

    #[test]
    fn long_fields_are_truncated() {
        let long = "A".repeat(5000);
        let out = format_value(&long);
        assert_eq!(out.chars().count(), MAX_FIELD_CHARS);
    }

    #[test]
    fn plain_values_stay_unquoted() {
        assert_eq!(format_value("CORP"), "CORP");
        assert_eq!(format_value(""), "");
        assert_eq!(format_value("1.2.3.4:5555"), "1.2.3.4:5555");
    }

    #[test]
    fn spaces_and_quotes_are_quoted_and_escaped() {
        assert_eq!(format_value("Mozilla/5.0 (X11)"), "\"Mozilla/5.0 (X11)\"");
        assert_eq!(format_value("say \"hi\""), "\"say \\\"hi\\\"\"");
    }

    #[test]
    fn adjacent_events_do_not_interleave() {
        use std::sync::Arc;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.log");
        let log = Arc::new(EventLog::open(path.to_str().unwrap()).unwrap());

        let mut handles = Vec::new();
        for t in 0..2 {
            let log = Arc::clone(&log);
            handles.push(std::thread::spawn(move || {
                for i in 0..100 {
                    log.event("load", &[("thread", &t.to_string()), ("i", &i.to_string())]);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 200);
        assert!(
            text.lines()
                .all(|l| l.starts_with("20") && l.contains("event=load"))
        );
    }

    #[test]
    fn dash_writes_to_stdout() {
        let log = EventLog::open("-").unwrap();
        log.event("startup", &[("listen", "0.0.0.0:5985")]);
    }
}
