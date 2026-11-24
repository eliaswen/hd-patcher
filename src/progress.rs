//! Lightweight, dependency-free progress reporting for the CLI.
//!
//! Step headers and status lines go to stdout. The live per-entry progress bar
//! is drawn on stderr, and only when stderr is a terminal, so piped or logged
//! output stays clean.

use std::io::{IsTerminal, Write};
use std::time::{Duration, Instant};

/// Print a numbered step header, e.g. `[2/3] Signing`.
pub fn step(n: usize, total: usize, title: &str) {
    println!("\n[{n}/{total}] {title}");
}

/// Print an indented detail line under the current step.
pub fn info(msg: &str) {
    println!("      {msg}");
}

/// Print a successful completion line for a step.
pub fn done(msg: &str, elapsed: Duration) {
    println!("      ✓ {msg} ({})", fmt_duration(elapsed));
}

pub fn fmt_duration(d: Duration) -> String {
    if d.as_secs() >= 60 {
        format!("{}m{:02}s", d.as_secs() / 60, d.as_secs() % 60)
    } else {
        format!("{:.1}s", d.as_secs_f64())
    }
}

/// Human-readable byte size.
pub fn fmt_bytes(n: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

/// A single-line progress bar over `total` items.
pub struct Bar {
    total: usize,
    live: bool,
    start: Instant,
    last_draw: Option<Instant>,
}

impl Bar {
    pub fn new(total: usize) -> Self {
        Self {
            total,
            live: std::io::stderr().is_terminal(),
            start: Instant::now(),
            last_draw: None,
        }
    }

    /// Update the bar after finishing `done` of `total` items; `label` names the
    /// item being processed. Redraws are throttled.
    pub fn update(&mut self, done: usize, label: &str) {
        if !self.live {
            return;
        }
        let now = Instant::now();
        if done < self.total {
            if let Some(last) = self.last_draw {
                if now.duration_since(last) < Duration::from_millis(50) {
                    return;
                }
            }
        }
        self.last_draw = Some(now);

        const WIDTH: usize = 24;
        let frac = if self.total == 0 {
            1.0
        } else {
            done as f64 / self.total as f64
        };
        let filled = (frac * WIDTH as f64).round() as usize;
        let bar = format!("{}{}", "█".repeat(filled), "░".repeat(WIDTH - filled));

        let label = truncate_left(label, 38);
        let mut err = std::io::stderr().lock();
        let _ = write!(
            err,
            "\r\x1b[2K      {bar} {:>3}% {done}/{} {label}",
            (frac * 100.0) as u32,
            self.total
        );
        let _ = err.flush();
    }

    fn clear(&self) {
        if self.live {
            let mut err = std::io::stderr().lock();
            let _ = write!(err, "\r\x1b[2K");
            let _ = err.flush();
        }
    }

    /// Clear the bar line and return the elapsed time.
    pub fn finish(self) -> Duration {
        self.clear();
        self.start.elapsed()
    }

    /// Print a line without corrupting the live bar.
    pub fn println(&self, msg: &str) {
        self.clear();
        println!("{msg}");
    }
}

/// Keep the tail of `s` (the interesting part of a path) within `max` chars.
fn truncate_left(s: &str, max: usize) -> String {
    let n = s.chars().count();
    if n <= max {
        s.to_string()
    } else {
        let tail: String = s.chars().skip(n - (max - 1)).collect();
        format!("…{tail}")
    }
}
