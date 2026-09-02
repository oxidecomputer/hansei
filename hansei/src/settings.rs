//! The `config` command: the session's render and listing defaults — the
//! values every per-command flag falls back to when it is not given.
//!
//! A key is spelled exactly like the flag it defaults (`config depth 6`
//! is the standing `--depth 6`), so nothing has two names. The values
//! live for the session only; a flag given on a command overrides them
//! for that command alone.

use anyhow::{Result, anyhow};

use std::cell::RefCell;
use std::io;

/// The session's standing defaults. The render keys fill
/// [`crate::RenderOpts`] outright, and `limit` backs the listing
/// commands' and trace's `--limit`.
pub(crate) struct Settings {
    pub(crate) depth: usize,
    pub(crate) ugly: bool,
    pub(crate) max_string_len: u64,
    pub(crate) max_array_values: u64,
    /// `None` is no limit — the default, and what `config limit off`
    /// returns to.
    pub(crate) limit: Option<usize>,
    /// Whether a listing on a terminal cuts its name columns — and a
    /// trace the names ending its frame lines — to the terminal's
    /// width, an ellipsis marking each cut. Output that is not a
    /// terminal is never cut, whatever this says.
    pub(crate) truncate_names: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            depth: 2,
            ugly: false,
            max_string_len: reify::DEFAULT_MAX_STRING_LEN,
            max_array_values: reify::DEFAULT_MAX_ARRAY_VALUES,
            limit: None,
            truncate_names: true,
        }
    }
}

/// The keys, in the order the listing prints them.
pub(crate) const KEYS: [&str; 6] = [
    "depth",
    "limit",
    "max-array-values",
    "max-string-len",
    "truncate-names",
    "ugly",
];

/// Answer `config`: print every key, print one, or change one.
pub(crate) fn exec_config(
    settings: &RefCell<Settings>,
    key: Option<&str>,
    value: Option<&str>,
    out: &mut dyn io::Write,
) -> Result<()> {
    let Some(key) = key else {
        let s = settings.borrow();
        for key in KEYS {
            writeln!(out, "{key:<18}{}", spell(&s, key))?;
        }
        return Ok(());
    };
    if !KEYS.contains(&key) {
        return Err(anyhow!(
            "no setting {key:?}; the keys are {}",
            KEYS.join(", ")
        ));
    }
    let Some(value) = value else {
        writeln!(out, "{key:<18}{}", spell(&settings.borrow(), key))?;
        return Ok(());
    };
    store(&mut settings.borrow_mut(), key, value)
}

/// The values a key accepts that are words rather than numbers — what
/// the prompt can offer after `config KEY`. A key that takes only a
/// count has none.
pub(crate) fn word_values(key: &str) -> &'static [&'static str] {
    match key {
        "limit" => &["off"],
        "truncate-names" | "ugly" => &["on", "off"],
        _ => &[],
    }
}

/// One key's current value, spelled the way `config` accepts it back.
fn spell(s: &Settings, key: &str) -> String {
    match key {
        "depth" => s.depth.to_string(),
        "limit" => match s.limit {
            Some(n) => n.to_string(),
            None => "off".to_string(),
        },
        "max-array-values" => s.max_array_values.to_string(),
        "max-string-len" => s.max_string_len.to_string(),
        "truncate-names" => on_off(s.truncate_names).to_string(),
        "ugly" => on_off(s.ugly).to_string(),
        _ => unreachable!("spell is called with keys from KEYS"),
    }
}

fn on_off(flag: bool) -> &'static str {
    match flag {
        true => "on",
        false => "off",
    }
}

/// Parse and store one key's new value. Each key parses its own value
/// so the error names what that key takes.
fn store(s: &mut Settings, key: &str, value: &str) -> Result<()> {
    match key {
        "depth" => s.depth = number(key, value)?,
        // `--limit 0` on a command means "show nothing"; here 0 would
        // read as "no limit", which `off` already spells, so the two
        // never disagree about what a zero means.
        "limit" => {
            s.limit = match value {
                "off" => None,
                _ => match number(key, value)? {
                    0 => {
                        return Err(anyhow!(
                            "config limit takes a count of at least 1, or `off` for no limit"
                        ));
                    }
                    n => Some(n),
                },
            }
        }
        "max-array-values" => s.max_array_values = number(key, value)?,
        "max-string-len" => s.max_string_len = number(key, value)?,
        "truncate-names" => s.truncate_names = switch(key, value)?,
        "ugly" => s.ugly = switch(key, value)?,
        _ => unreachable!("store is called with keys from KEYS"),
    }
    Ok(())
}

fn switch(key: &str, value: &str) -> Result<bool> {
    match value {
        "on" => Ok(true),
        "off" => Ok(false),
        other => Err(anyhow!("config {key} takes on or off, got {other:?}")),
    }
}

fn number<N: std::str::FromStr>(key: &str, value: &str) -> Result<N> {
    value
        .parse()
        .map_err(|_| anyhow!("config {key} takes a number, got {value:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(settings: &RefCell<Settings>, key: Option<&str>, value: Option<&str>) -> String {
        let mut out = Vec::new();
        exec_config(settings, key, value, &mut out).expect("config answers");
        String::from_utf8(out).expect("config output is UTF-8")
    }

    /// Bare `config` prints every key at its default; each key prints
    /// alone; a changed value reads back both ways.
    #[test]
    fn test_config_round_trips_every_key() {
        let settings = RefCell::new(Settings::default());
        let listing = run(&settings, None, None);
        assert_eq!(
            listing,
            "depth             2\n\
             limit             off\n\
             max-array-values  128\n\
             max-string-len    131072\n\
             truncate-names    on\n\
             ugly              off\n"
        );

        for (key, value, spelled) in [
            ("depth", "7", "7"),
            ("limit", "100", "100"),
            ("max-array-values", "3", "3"),
            ("max-string-len", "64", "64"),
            ("truncate-names", "off", "off"),
            ("ugly", "on", "on"),
        ] {
            assert_eq!(run(&settings, Some(key), Some(value)), "");
            let line = run(&settings, Some(key), None);
            assert_eq!(line, format!("{key:<18}{spelled}\n"));
        }
        assert_eq!(settings.borrow().depth, 7);
        assert_eq!(settings.borrow().limit, Some(100));
        assert_eq!(settings.borrow().max_array_values, 3);
        assert_eq!(settings.borrow().max_string_len, 64);
        assert!(!settings.borrow().truncate_names);
        assert!(settings.borrow().ugly);
    }

    /// `config limit off` is the way back to no limit, and 0 — which the
    /// per-command flag reads as "show nothing" — is refused rather
    /// than silently meaning the opposite here.
    #[test]
    fn test_config_limit_off_is_the_unset_and_zero_is_refused() {
        let settings = RefCell::new(Settings::default());
        run(&settings, Some("limit"), Some("40"));
        assert_eq!(settings.borrow().limit, Some(40));
        run(&settings, Some("limit"), Some("off"));
        assert_eq!(settings.borrow().limit, None);

        let err = exec_config(&settings, Some("limit"), Some("0"), &mut Vec::new()).unwrap_err();
        assert_eq!(
            err.to_string(),
            "config limit takes a count of at least 1, or `off` for no limit"
        );
    }

    /// The errors name the key and what it takes; an unknown key lists
    /// the keys there are.
    #[test]
    fn test_config_errors_name_the_key_and_its_values() {
        let settings = RefCell::new(Settings::default());
        let err = |key, value| {
            exec_config(&settings, Some(key), value, &mut Vec::new())
                .unwrap_err()
                .to_string()
        };
        assert_eq!(
            err("no-such-key", None),
            "no setting \"no-such-key\"; the keys are depth, limit, \
             max-array-values, max-string-len, truncate-names, ugly"
        );
        assert_eq!(
            err("depth", Some("x")),
            "config depth takes a number, got \"x\""
        );
        assert_eq!(
            err("ugly", Some("yes")),
            "config ugly takes on or off, got \"yes\""
        );
        assert_eq!(
            err("truncate-names", Some("1")),
            "config truncate-names takes on or off, got \"1\""
        );
    }
}
