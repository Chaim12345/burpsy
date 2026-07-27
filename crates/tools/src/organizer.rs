//! Organizer — the operator's shortlist: saved exchanges with notes and a colour.
//!
//! # Why an id and a note, and nothing else
//!
//! The Organizer exists because an engagement produces tens of thousands of exchanges and maybe
//! forty that matter. It is a working set, not a second copy of history, so an item holds the
//! `TrafficStore` exchange id and the operator's own words. That is safe here in a way it would not
//! be in most tools: the store is append-only and never evicts, so a saved id cannot dangle.
//!
//! The colour set is Burp's `HighlightColor` verbatim (`Zpha.java`: NONE, RED, ORANGE, YELLOW,
//! GREEN, CYAN, BLUE, PINK, MAGENTA, GRAY). Copying it costs nothing and means colours survive
//! import and export in either direction.
//!
//! Items stay in the order they were added rather than newest-first. A shortlist is something the
//! operator builds deliberately, usually in the order the attack chain runs; re-sorting it under
//! them would destroy that.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Highlight {
    #[default]
    None,
    Red,
    Orange,
    Yellow,
    Green,
    Cyan,
    Blue,
    Pink,
    Magenta,
    Gray,
}

impl Highlight {
    pub fn as_str(self) -> &'static str {
        match self {
            Highlight::None => "none",
            Highlight::Red => "red",
            Highlight::Orange => "orange",
            Highlight::Yellow => "yellow",
            Highlight::Green => "green",
            Highlight::Cyan => "cyan",
            Highlight::Blue => "blue",
            Highlight::Pink => "pink",
            Highlight::Magenta => "magenta",
            Highlight::Gray => "gray",
        }
    }

    /// Unknown names become [`Highlight::None`] rather than an error: a colour is a label, and
    /// refusing to save an item because its colour was misspelled would be absurd.
    pub fn parse(s: &str) -> Highlight {
        match s.trim().to_ascii_lowercase().as_str() {
            "red" => Highlight::Red,
            "orange" => Highlight::Orange,
            "yellow" => Highlight::Yellow,
            "green" => Highlight::Green,
            "cyan" => Highlight::Cyan,
            "blue" => Highlight::Blue,
            "pink" => Highlight::Pink,
            "magenta" => Highlight::Magenta,
            "gray" | "grey" => Highlight::Gray,
            _ => Highlight::None,
        }
    }

    pub const ALL: [Highlight; 10] = [
        Highlight::None,
        Highlight::Red,
        Highlight::Orange,
        Highlight::Yellow,
        Highlight::Green,
        Highlight::Cyan,
        Highlight::Blue,
        Highlight::Pink,
        Highlight::Magenta,
        Highlight::Gray,
    ];
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    pub id: u64,
    /// The exchange in the `TrafficStore`. No bytes are copied here.
    pub exchange: u64,
    /// A one-line label, usually `METHOD /path`.
    pub title: String,
    pub note: String,
    pub highlight: Highlight,
    /// Epoch milliseconds, supplied by the caller so this crate stays free of ambient state.
    pub added_ms: u64,
}

#[derive(Debug, Default)]
pub struct Organizer {
    inner: RwLock<Vec<Item>>,
    next: AtomicU64,
}

impl Organizer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&self, exchange: u64, title: impl Into<String>, added_ms: u64) -> u64 {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.inner.write().push(Item {
            id,
            exchange,
            title: title.into(),
            note: String::new(),
            highlight: Highlight::None,
            added_ms,
        });
        id
    }

    pub fn get(&self, id: u64) -> Option<Item> {
        self.inner.read().iter().find(|i| i.id == id).cloned()
    }

    /// Replace the note. Returns false when the item is gone.
    pub fn set_note(&self, id: u64, note: impl Into<String>) -> bool {
        self.edit(id, |i| i.note = note.into())
    }

    pub fn set_highlight(&self, id: u64, highlight: Highlight) -> bool {
        self.edit(id, |i| i.highlight = highlight)
    }

    pub fn set_title(&self, id: u64, title: impl Into<String>) -> bool {
        self.edit(id, |i| i.title = title.into())
    }

    fn edit(&self, id: u64, f: impl FnOnce(&mut Item)) -> bool {
        let mut g = self.inner.write();
        match g.iter_mut().find(|i| i.id == id) {
            Some(i) => {
                f(i);
                true
            }
            None => false,
        }
    }

    pub fn remove(&self, id: u64) -> bool {
        let mut g = self.inner.write();
        let before = g.len();
        g.retain(|i| i.id != id);
        g.len() != before
    }

    /// Everything, in the order the operator added it.
    pub fn all(&self) -> Vec<Item> {
        self.inner.read().clone()
    }

    pub fn with_highlight(&self, highlight: Highlight) -> Vec<Item> {
        self.inner
            .read()
            .iter()
            .filter(|i| i.highlight == highlight)
            .cloned()
            .collect()
    }

    /// Whether this exchange is already on the shortlist, so the UI can show the star filled.
    pub fn contains_exchange(&self, exchange: u64) -> bool {
        self.inner.read().iter().any(|i| i.exchange == exchange)
    }

    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_item_is_saved_annotated_and_read_back() {
        let o = Organizer::new();
        let id = o.add(42, "POST /login", 1_700_000_000_000);
        assert!(o.set_note(id, "reflects the email field into the error page"));
        assert!(o.set_highlight(id, Highlight::Red));
        let i = o.get(id).unwrap();
        assert_eq!(i.exchange, 42);
        assert_eq!(i.title, "POST /login");
        assert_eq!(i.note, "reflects the email field into the error page");
        assert_eq!(i.highlight, Highlight::Red);
        assert_eq!(i.added_ms, 1_700_000_000_000);
    }

    #[test]
    fn items_keep_the_order_the_operator_added_them() {
        let o = Organizer::new();
        for (i, t) in ["first", "second", "third"].iter().enumerate() {
            o.add(i as u64, *t, 0);
        }
        assert_eq!(
            o.all().iter().map(|i| i.title.as_str()).collect::<Vec<_>>(),
            vec!["first", "second", "third"]
        );
    }

    #[test]
    fn removing_an_item_leaves_the_rest_addressable_by_their_original_ids() {
        let o = Organizer::new();
        let a = o.add(1, "a", 0);
        let b = o.add(2, "b", 0);
        assert!(o.remove(a));
        assert!(!o.remove(a), "removing twice reports nothing was removed");
        assert!(o.get(a).is_none());
        assert_eq!(o.get(b).unwrap().title, "b");
        assert_eq!(o.len(), 1);
    }

    #[test]
    fn editing_a_removed_item_reports_failure_instead_of_panicking() {
        let o = Organizer::new();
        let id = o.add(1, "a", 0);
        o.remove(id);
        assert!(!o.set_note(id, "x"));
        assert!(!o.set_highlight(id, Highlight::Blue));
        assert!(!o.set_title(id, "y"));
    }

    #[test]
    fn the_same_exchange_can_be_saved_twice_but_is_reported_as_present_once() {
        let o = Organizer::new();
        o.add(9, "GET /a", 0);
        o.add(9, "GET /a again, with a different note", 0);
        assert!(o.contains_exchange(9));
        assert!(!o.contains_exchange(10));
        assert_eq!(
            o.len(),
            2,
            "duplicates are the operator's choice, not an error"
        );
    }

    #[test]
    fn filtering_by_colour_returns_only_that_colour() {
        let o = Organizer::new();
        let a = o.add(1, "a", 0);
        let b = o.add(2, "b", 0);
        o.add(3, "c", 0);
        o.set_highlight(a, Highlight::Green);
        o.set_highlight(b, Highlight::Green);
        assert_eq!(o.with_highlight(Highlight::Green).len(), 2);
        assert_eq!(o.with_highlight(Highlight::None).len(), 1);
    }

    #[test]
    fn colour_names_round_trip_and_a_misspelling_degrades_to_none() {
        for h in Highlight::ALL {
            assert_eq!(Highlight::parse(h.as_str()), h);
        }
        assert_eq!(Highlight::parse("grey"), Highlight::Gray);
        assert_eq!(Highlight::parse("chartreuse"), Highlight::None);
    }
}
