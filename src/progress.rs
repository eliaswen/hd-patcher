//! Progress reporting. The library reports through [`Progress`]; the CLI uses
//! [`Console`], and an app can forward the same calls to its own UI.

use std::io::{IsTerminal, Write};
use std::time::{Duration, Instant};

/// Receives progress from [`crate::patch`]. Every method has a no-op default.
pub trait Progress {
    /// A numbered step starts, e.g. `2 of 3: Signing`.
    fn step(&mut self, _index: usize, _total: usize, _title: &str) {}
    /// A detail line under the current step, such as an applied edit.
    fn info(&mut self, _message: &str) {}
    /// `done` of `total` archive entries are finished; `name` is the current one.
    fn entry(&mut self, _done: usize, _total: usize, _name: &str) {}
    /// The current step finished.
    fn done(&mut self, _message: &str, _elapsed: Duration) {}
}

/// Discards all progress.
pub struct Silent;

impl Progress for Silent {}

/// Step headers and detail lines on stdout, and a live per-entry bar on stderr
/// when stderr is a terminal that understands ANSI escapes (on Windows, the
/// console is switched to virtual-terminal mode; without it there is no bar).
pub struct Console {
    live: bool,
    drawn: bool,
    last_draw: Option<Instant>,
}

impl Default for Console {
    fn default() -> Self {
        Self::new()
    }
}

impl Console {
    pub fn new() -> Self {
        Self {
            live: std::io::stderr().is_terminal() && enable_ansi(),
            drawn: false,
            last_draw: None,
        }
    }

    fn clear(&mut self) {
        if self.drawn {
            let mut err = std::io::stderr().lock();
            let _ = write!(err, "\r\x1b[2K");
            let _ = err.flush();
            self.drawn = false;
        }
    }
}

impl Progress for Console {
    fn step(&mut self, index: usize, total: usize, title: &str) {
        self.clear();
        println!("\n[{index}/{total}] {title}");
    }

    fn info(&mut self, message: &str) {
        self.clear();
        println!("      {message}");
    }

    fn entry(&mut self, done: usize, total: usize, name: &str) {
        if !self.live {
            return;
        }
        let now = Instant::now();
        if done < total
            && self
                .last_draw
                .is_some_and(|last| now.duration_since(last) < Duration::from_millis(50))
        {
            return;
        }
        self.last_draw = Some(now);

        const WIDTH: usize = 24;
        let frac = if total == 0 {
            1.0
        } else {
            done as f64 / total as f64
        };
        let filled = (frac * WIDTH as f64).round() as usize;
        let bar = format!("{}{}", "█".repeat(filled), "░".repeat(WIDTH - filled));
        let label = truncate_left(name, 38);
        let mut err = std::io::stderr().lock();
        let _ = write!(
            err,
            "\r\x1b[2K      {bar} {:>3}% {done}/{total} {label}",
            (frac * 100.0) as u32
        );
        let _ = err.flush();
        self.drawn = true;
    }

    fn done(&mut self, message: &str, elapsed: Duration) {
        self.clear();
        println!("      ✓ {message} ({})", fmt_duration(elapsed));
    }
}

/// Turn on ANSI escape processing for stderr. Always true off Windows.
#[cfg(windows)]
fn enable_ansi() -> bool {
    use windows_sys::Win32::System::Console::{
        ENABLE_VIRTUAL_TERMINAL_PROCESSING, GetConsoleMode, GetStdHandle, STD_ERROR_HANDLE,
        SetConsoleMode,
    };
    // SAFETY: plain Win32 calls on the process's own standard handle.
    unsafe {
        let handle = GetStdHandle(STD_ERROR_HANDLE);
        let mut mode = 0;
        if GetConsoleMode(handle, &mut mode) == 0 {
            return false;
        }
        mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0
            || SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
    }
}

#[cfg(not(windows))]
fn enable_ansi() -> bool {
    true
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
