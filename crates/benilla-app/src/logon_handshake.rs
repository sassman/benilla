//! Which SRP6 handshake a logon speaks: benilla's own CVar `logonHandshake`.
//!
//! Deviation: the reference has one logon handshake and no setting for it. benilla names the
//! one to speak because a server that knows the strong one ([`Handshake::Strong`]) keeps the
//! password off the stock handshake's 256-bit group, and the choice has to be the player's: a
//! logon that fell back by itself could be pushed back by whoever sits on the line.

use benilla_protocol::Handshake;
use benilla_ui::script::{CvarRows, CvarVerdict};

pub(crate) const CVAR_LOGON_HANDSHAKE: &str = "logonHandshake";
/// The 1.12.1 client's handshake, which every realmd speaks.
pub(crate) const DEFAULT_LOGON_HANDSHAKE: &str = "stock";

/// The handshake a CVar value names, `None` for one that names neither.
pub(crate) fn parse(value: &str) -> Option<Handshake> {
    match value.trim().to_ascii_lowercase().as_str() {
        "stock" => Some(Handshake::Stock),
        "strong" => Some(Handshake::Strong),
        _ => None,
    }
}

/// The row's refusal: a value that names no handshake is not stored, so a typo cannot stand
/// for the stock one.
pub(crate) fn check(value: &str, _applied: &str, _rows: CvarRows<'_>) -> CvarVerdict {
    if parse(value).is_some() {
        CvarVerdict {
            accept: true,
            lines: Vec::new(),
        }
    } else {
        CvarVerdict {
            accept: false,
            lines: vec!["logonHandshake must be stock or strong.".to_string()],
        }
    }
}

/// The handshake the next logon speaks, from the row's applied value: the default when there
/// is no row to read. A value the config file saved skips [`check`], as every row's does, and
/// one that names nothing speaks the strong handshake, not the stock one: whoever wrote it
/// wanted something other than the default, and a strong logon a server does not know ends
/// with that said, where a stock one would send the password the weak way unnoticed.
pub(crate) fn applied(value: Option<&str>) -> Handshake {
    let Some(value) = value else {
        return Handshake::default();
    };
    parse(value).unwrap_or_else(|| {
        bevy::log::warn!("cvar logonHandshake: '{value}' names no handshake, speaking strong");
        Handshake::Strong
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_the_stock_handshake() {
        assert_eq!(parse(DEFAULT_LOGON_HANDSHAKE), Some(Handshake::Stock));
    }

    #[test]
    fn a_value_names_a_handshake_or_nothing() {
        assert_eq!(parse("strong"), Some(Handshake::Strong));
        assert_eq!(parse(" Strong "), Some(Handshake::Strong));
        assert_eq!(parse("STOCK"), Some(Handshake::Stock));
        for other in ["", "1", "stronger", "srp6"] {
            assert_eq!(parse(other), None, "{other:?}");
        }
    }

    #[test]
    fn the_row_refuses_a_value_that_names_no_handshake() {
        let rows = |_: &str| None;
        assert!(check("strong", "stock", &rows).accept);
        assert!(!check("storng", "stock", &rows).accept);
    }

    /// A saved typo must not turn into the weak handshake.
    #[test]
    fn a_saved_value_that_names_nothing_never_speaks_stock() {
        assert_eq!(applied(None), Handshake::Stock);
        assert_eq!(applied(Some("stock")), Handshake::Stock);
        assert_eq!(applied(Some("strong")), Handshake::Strong);
        assert_eq!(applied(Some("storng")), Handshake::Strong);
    }
}
