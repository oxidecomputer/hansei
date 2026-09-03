// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Display folding of Rust type names.
//!
//! Debug info spells type names in full — coroutine environments carry
//! their `{async_fn_env#0}` marker, std containers their whole path,
//! generic argument lists the defaulted allocator — and the read side
//! prints a lot of them. The fold here shortens a name for *display
//! only*: nothing recorded in a bundle changes, and anything a command
//! accepts back is accepted in the raw spelling too (lookups compare
//! folded-to-folded when the raw name misses).
//!
//! The fold lives beside [`crate::symbols`]'s comparison rules on
//! purpose: display catches up to what the matcher already treats as
//! noise (whitespace, the default allocator) and must never diverge
//! from it.

use crate::schema::Bundle;

use foldhash::{HashMap, HashMapExt};

use std::borrow::Cow;

/// The coroutine-environment markers rustc appends to an async item's
/// path. Only index 0 folds away: a higher index tells two coroutines
/// from one item apart, which is exactly what a display name must keep.
const ENV_MARKERS: [&str; 3] = [
    "::{async_fn_env#0}",
    "::{async_block_env#0}",
    "::{async_closure_env#0}",
];

/// Std paths whose short name is unambiguous, folded to it wherever a
/// whole path segment spells them out.
const STD_SHORTENINGS: [(&str, &str); 12] = [
    ("alloc::vec::Vec", "Vec"),
    ("alloc::string::String", "String"),
    ("alloc::boxed::Box", "Box"),
    ("alloc::sync::Arc", "Arc"),
    ("alloc::borrow::Cow", "Cow"),
    ("core::option::Option", "Option"),
    ("core::result::Result", "Result"),
    ("core::pin::Pin", "Pin"),
    ("core::future::future::Future", "Future"),
    ("core::marker::Send", "Send"),
    ("core::marker::Sync", "Sync"),
    ("core::ops::control_flow::ControlFlow", "ControlFlow"),
];

/// The defaulted allocator argument, dropped from the generic list that
/// spells it out — the same elision [`crate::symbols`]'s comparison key
/// applies.
const GLOBAL_ALLOCATOR: &str = "alloc::alloc::Global";

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Whether a path starting at a position preceded by `before` starts a
/// crate root: nothing, or a delimiter — but not `:`, behind which
/// `alloc` would be somebody's module rather than the crate.
fn opens_path(before: Option<char>) -> bool {
    before.is_none_or(|c| !is_ident(c) && c != ':')
}

/// Whether a match ending just before `after` ends a path segment.
fn closes_segment(after: Option<char>) -> bool {
    after.is_none_or(|c| !is_ident(c))
}

/// The impl-path substitutions of one bundle's [`ImplTable`]
/// (`crate::schema::ImplTable`), resolved to owned strings so the fold
/// can consume them without borrowing the bundle. Built once per loaded
/// bundle; [`ImplFold::default`] substitutes nothing, which is the
/// right fold for a name with no bundle behind it (tests, symbols).
#[derive(Clone, Debug, Default)]
pub struct ImplFold {
    map: HashMap<String, String>,
}

impl ImplFold {
    /// The substitutions `bundle` carries. A ref its own string table
    /// cannot resolve is skipped — [`Bundle::validate`] already refuses
    /// such a bundle loudly.
    pub fn for_bundle(bundle: &Bundle) -> Self {
        let mut map = HashMap::with_capacity(bundle.impls.entries.len());
        for &(path, self_type) in &bundle.impls.entries {
            if let (Some(path), Some(self_type)) =
                (bundle.strings.get(path), bundle.strings.get(self_type))
            {
                map.insert(path.to_owned(), self_type.to_owned());
            }
        }
        Self { map }
    }

    /// A fold from literal `(impl path, self type)` pairs, for tests
    /// and tools that have no bundle in hand.
    pub fn from_pairs<K: Into<String>, V: Into<String>>(
        pairs: impl IntoIterator<Item = (K, V)>,
    ) -> Self {
        Self {
            map: pairs
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        }
    }

    /// Replace every known `a::b::{impl#N}` prefix in `name` with its
    /// impl's self type path, wherever the prefix opens a path — at the
    /// top of the name or inside a generic argument. The longest known
    /// prefix wins, so a nested impl path substitutes whole. Borrows
    /// when nothing substitutes.
    fn substitute<'a>(&self, name: &'a str) -> Cow<'a, str> {
        if self.map.is_empty() || !name.contains("{impl#") {
            return Cow::Borrowed(name);
        }
        let mut out: Option<String> = None;
        let mut pos = 0;
        while pos < name.len() {
            let before = name[..pos].chars().next_back();
            let rest = &name[pos..];
            let sub = if opens_path(before) {
                impl_prefixes(rest)
                    .rev()
                    .find_map(|end| self.map.get(&rest[..end]).map(|to| (end, to)))
            } else {
                None
            };
            if let Some((end, to)) = sub {
                out.get_or_insert_with(|| name[..pos].to_string())
                    .push_str(to);
                pos += end;
                continue;
            }
            let c = rest.chars().next().expect("pos is on a char boundary");
            if let Some(out) = &mut out {
                out.push(c);
            }
            pos += c.len_utf8();
        }
        match out {
            Some(subbed) => Cow::Owned(subbed),
            None => Cow::Borrowed(name),
        }
    }
}

/// The end offsets in `rest` of every path prefix closing with an
/// `{impl#N}` segment, shortest first: for
/// `a::{impl#0}::m::{impl#1}::rest` the offsets after `{impl#0}` and
/// after `{impl#1}`. The scan stops at the first segment that is
/// neither an identifier nor such a marker, which is where a name's
/// path run ends anyway (a generic list, an env marker).
pub fn impl_prefixes(rest: &str) -> impl DoubleEndedIterator<Item = usize> {
    let mut ends = Vec::new();
    let mut pos = 0;
    loop {
        let seg = &rest[pos..];
        let end = if let Some(digits) = seg.strip_prefix("{impl#") {
            let n = digits.bytes().take_while(u8::is_ascii_digit).count();
            match (n, digits.as_bytes().get(n)) {
                (1.., Some(b'}')) => {
                    ends.push(pos + "{impl#".len() + n + 1);
                    pos + "{impl#".len() + n + 1
                }
                _ => break,
            }
        } else {
            let n = seg.chars().take_while(|&c| is_ident(c)).count();
            if n == 0 {
                break;
            }
            pos + seg.chars().take(n).map(char::len_utf8).sum::<usize>()
        };
        match rest[end..].strip_prefix("::") {
            Some(_) => pos = end + 2,
            None => break,
        }
    }
    ends.into_iter()
}

/// Every impl path occurring in `text` wherever a path opens — at the
/// top or inside a generic argument — nested prefixes included:
/// `C<a::{impl#0}::m::{impl#1}::go>` mentions `a::{impl#0}` and
/// `a::{impl#0}::m::{impl#1}`. What extraction scans the string table
/// with, so a bundle records only the impl entries its strings mention.
pub fn impl_paths(text: &str) -> Vec<&str> {
    let mut paths = Vec::new();
    if !text.contains("{impl#") {
        return paths;
    }
    let mut pos = 0;
    while pos < text.len() {
        let before = text[..pos].chars().next_back();
        let rest = &text[pos..];
        if opens_path(before) {
            let mut last = None;
            for prefix_end in impl_prefixes(rest) {
                paths.push(&rest[..prefix_end]);
                last = Some(prefix_end);
            }
            if let Some(end) = last {
                pos += end;
                continue;
            }
        }
        pos += rest
            .chars()
            .next()
            .expect("pos is on a char boundary")
            .len_utf8();
    }
    paths
}

/// Fold `name` for display: substitute impl-block paths with their self
/// types per `impls`, drop `#0` coroutine-env markers wherever they
/// appear (generic arguments included), shorten the std paths of
/// [`STD_SHORTENINGS`] on path-segment boundaries, and drop a spelled
/// out default allocator closing a generic argument list. Borrows when
/// nothing folds, which most names do not need.
pub fn fold_type_name<'a>(name: &'a str, impls: &ImplFold) -> Cow<'a, str> {
    match impls.substitute(name) {
        Cow::Borrowed(name) => fold_markers(name),
        Cow::Owned(subbed) => Cow::Owned(fold_markers(&subbed).into_owned()),
    }
}

/// The marker folds of [`fold_type_name`], after impl substitution.
fn fold_markers(name: &str) -> Cow<'_, str> {
    let mut out: Option<String> = None;
    let mut pos = 0;
    // Copy everything before the first fold lazily, so an unchanged
    // name is returned borrowed.
    let push = |out: &mut Option<String>, upto: usize, text: &str| {
        out.get_or_insert_with(|| name[..upto].to_string())
            .push_str(text);
    };
    while pos < name.len() {
        let rest = &name[pos..];
        if let Some(marker) = ENV_MARKERS.iter().find(|m| rest.starts_with(**m)) {
            push(&mut out, pos, "");
            pos += marker.len();
            continue;
        }
        if let Some(len) = allocator_elision_len(rest) {
            push(&mut out, pos, ">");
            pos += len;
            continue;
        }
        let before = name[..pos].chars().next_back();
        let shortened = STD_SHORTENINGS.iter().find(|(long, _)| {
            rest.starts_with(long)
                && opens_path(before)
                && closes_segment(rest[long.len()..].chars().next())
        });
        if let Some((long, short)) = shortened {
            push(&mut out, pos, short);
            pos += long.len();
            continue;
        }
        let c = rest.chars().next().expect("pos is on a char boundary");
        if let Some(out) = &mut out {
            out.push(c);
        }
        pos += c.len_utf8();
    }
    match out {
        Some(folded) => Cow::Owned(folded),
        None => Cow::Borrowed(name),
    }
}

/// The length of a `, alloc::alloc::Global>` run opening at the start of
/// `rest` — the comma, the allocator, the closing bracket, and whatever
/// spaces a demangler laid between them — or `None` where `rest` opens
/// with anything else.
fn allocator_elision_len(rest: &str) -> Option<usize> {
    let tail = rest.strip_prefix(',')?;
    let allocator = tail.trim_start();
    let inner = allocator.strip_prefix(GLOBAL_ALLOCATOR)?;
    let close = inner.trim_start();
    close.starts_with('>').then(|| {
        rest.len() - close.len() + 1 // the '>' itself
    })
}

/// The kind word for a coroutine's generated environment name, judged
/// on the outermost path — a wrapper such as
/// `PollFn<foo::{async_fn_env#0}>` is not itself an async fn — or
/// `None` for anything that is not a coroutine env at all.
pub fn coroutine_kind(name: &str) -> Option<&'static str> {
    let mut outer = String::with_capacity(name.len());
    let mut generic_depth = 0usize;
    for c in name.chars() {
        match c {
            '<' => generic_depth += 1,
            '>' => generic_depth = generic_depth.saturating_sub(1),
            _ if generic_depth == 0 => outer.push(c),
            _ => {}
        }
    }
    let last = outer.rsplit("::").next()?;
    let kind = |prefix, kind| (last.starts_with(prefix) && last.ends_with('}')).then_some(kind);
    kind("{async_fn_env#", "async fn")
        .or_else(|| kind("{async_block_env#", "async block"))
        .or_else(|| kind("{async_closure_env#", "async closure"))
}

/// A future's display name where no kind column carries the kind for
/// it: the kind word joined to the folded name — `async fn foo::bar`,
/// or `future tokio::time::Sleep` for a plain future.
pub fn display_future_name(name: &str, impls: &ImplFold) -> String {
    let kind = coroutine_kind(name).unwrap_or("future");
    format!("{kind} {}", fold_type_name(name, impls))
}

/// Strip the kind word [`display_future_name`] joined, so a displayed
/// name pasted whole into a lookup still names its type.
pub fn strip_kind_prefix(name: &str) -> &str {
    // "async fn " before "async ", or the neutral word would eat the
    // specific ones down to "fn ".
    for kind in [
        "async fn ",
        "async block ",
        "async closure ",
        "async ",
        "future ",
    ] {
        if let Some(rest) = name.strip_prefix(kind) {
            return rest;
        }
    }
    name
}

#[cfg(test)]
mod tests {
    use super::{ImplFold, coroutine_kind, impl_prefixes, strip_kind_prefix};

    use std::borrow::Cow;

    /// The fold with no impl substitutions, which most cases exercise.
    fn fold_type_name(name: &str) -> Cow<'_, str> {
        super::fold_type_name(name, &ImplFold::default())
    }

    fn display_future_name(name: &str) -> String {
        super::display_future_name(name, &ImplFold::default())
    }

    #[test]
    fn test_impl_paths_substitute_their_self_types() {
        let impls = ImplFold::from_pairs([
            ("tokio::sync::mutex::{impl#10}", "tokio::sync::mutex::Mutex"),
            ("alloc::sync::{impl#12}", "alloc::sync::Arc"),
        ]);
        assert_eq!(
            super::fold_type_name(
                "tokio::sync::mutex::{impl#10}::lock::{async_fn_env#0}<()>",
                &impls
            ),
            "tokio::sync::mutex::Mutex::lock<()>"
        );
        // Inside a generic argument, composed with the other folds —
        // and the substituted self type is itself display-folded.
        assert_eq!(
            super::fold_type_name(
                "tokio::time::timeout::Timeout<tokio::sync::mutex::{impl#10}::lock::{async_fn_env#0}<()>>",
                &impls
            ),
            "tokio::time::timeout::Timeout<tokio::sync::mutex::Mutex::lock<()>>"
        );
        assert_eq!(
            super::fold_type_name("alloc::sync::{impl#12}::drop_slow<u8>", &impls),
            "Arc::drop_slow<u8>"
        );
        // An impl the table does not know stays spelled as-is; so does
        // a known path where it does not open a whole path.
        assert_eq!(
            super::fold_type_name("tokio::sync::mutex::{impl#11}::try_lock<()>", &impls),
            "tokio::sync::mutex::{impl#11}::try_lock<()>"
        );
        assert_eq!(
            super::fold_type_name("my::tokio::sync::mutex::{impl#10}::lock<()>", &impls),
            "my::tokio::sync::mutex::{impl#10}::lock<()>"
        );
    }

    /// A nested impl path substitutes whole: the longest known prefix
    /// wins over its own outer impl's entry.
    #[test]
    fn test_nested_impl_paths_substitute_longest_first() {
        let impls = ImplFold::from_pairs([
            ("a::{impl#0}", "a::A"),
            ("a::{impl#0}::m::{impl#1}", "a::m::B"),
        ]);
        assert_eq!(
            super::fold_type_name("a::{impl#0}::m::{impl#1}::run", &impls),
            "a::m::B::run"
        );
        assert_eq!(super::fold_type_name("a::{impl#0}::go", &impls), "a::A::go");
    }

    /// The substitution is part of the fold's idempotency contract: a
    /// substituted name must pass through the fold unchanged.
    #[test]
    fn test_substitution_is_idempotent() {
        let impls = ImplFold::from_pairs([("b::{impl#3}", "b::B")]);
        let once = super::fold_type_name("c::C<b::{impl#3}::go::{closure_env#0}>", &impls);
        assert_eq!(once, "c::C<b::B::go::{closure_env#0}>");
        assert_eq!(super::fold_type_name(&once, &impls), once.as_ref());
    }

    #[test]
    fn test_impl_prefixes_walks_the_path_run() {
        let name = "a::{impl#0}::m::{impl#12}::rest::{async_fn_env#0}";
        let ends: Vec<usize> = impl_prefixes(name).collect();
        assert_eq!(ends.len(), 2);
        assert_eq!(&name[..ends[0]], "a::{impl#0}");
        assert_eq!(&name[..ends[1]], "a::{impl#0}::m::{impl#12}");
        assert_eq!(impl_prefixes("a::b::C<d::{impl#0}::e>").count(), 0);
        assert_eq!(impl_prefixes("{impl#}::x").count(), 0);
        assert_eq!(impl_prefixes("{impl#7}::x").count(), 1);
    }

    #[test]
    fn test_env_markers_fold_wherever_they_appear() {
        assert_eq!(
            fold_type_name("oximeter_producer::registration_task::{async_fn_env#0}"),
            "oximeter_producer::registration_task"
        );
        assert_eq!(
            fold_type_name("futurelock::main::{async_block#0}::{async_block_env#0}"),
            "futurelock::main::{async_block#0}"
        );
        // Inside generic arguments, and with the generic list kept on
        // the folded name.
        assert_eq!(
            fold_type_name("tokio::time::timeout::Timeout<mpsc::recv::{async_fn_env#0}<u32>>"),
            "tokio::time::timeout::Timeout<mpsc::recv<u32>>"
        );
        assert_eq!(
            fold_type_name("tokio::sync::mutex::{impl#10}::lock::{async_fn_env#0}<()>"),
            "tokio::sync::mutex::{impl#10}::lock<()>"
        );
    }

    /// An env index above zero tells two coroutines from one item
    /// apart, so it survives the fold — as does a plain closure env,
    /// which the fold never touches.
    #[test]
    fn test_discriminating_env_indexes_stay() {
        for name in [
            "crate::work::{async_fn_env#1}",
            "crate::work::{async_block_env#2}",
            "poll_fn::PollFn<crate::work::{closure_env#0}>",
        ] {
            assert_eq!(fold_type_name(name), name);
            assert!(matches!(fold_type_name(name), Cow::Borrowed(_)));
        }
    }

    #[test]
    fn test_std_paths_shorten_on_segment_boundaries() {
        assert_eq!(fold_type_name("alloc::vec::Vec<u8>"), "Vec<u8>");
        assert_eq!(
            fold_type_name("core::option::Option<alloc::string::String>"),
            "Option<String>"
        );
        assert_eq!(
            fold_type_name("core::ops::control_flow::ControlFlow<(), app::Inventory>"),
            "ControlFlow<(), app::Inventory>"
        );
        assert_eq!(
            fold_type_name(
                "core::pin::Pin<alloc::boxed::Box<dyn core::future::future::Future<Output=()> + core::marker::Send>>"
            ),
            "Pin<Box<dyn Future<Output=()> + Send>>"
        );
        // Not on a crate root: someone's own module spelling the same
        // path is their name, not std's.
        assert_eq!(
            fold_type_name("myalloc::vec::Vec<u8>"),
            "myalloc::vec::Vec<u8>"
        );
        assert_eq!(
            fold_type_name("mycrate::alloc::vec::Vec<u8>"),
            "mycrate::alloc::vec::Vec<u8>"
        );
        // Not into a longer segment: VecDeque is not Vec.
        assert_eq!(
            fold_type_name("alloc::collections::vec_deque::VecDeque<alloc::vec::VecExt>"),
            "alloc::collections::vec_deque::VecDeque<alloc::vec::VecExt>"
        );
    }

    #[test]
    fn test_default_allocators_fold_away() {
        assert_eq!(
            fold_type_name("alloc::vec::Vec<u8, alloc::alloc::Global>"),
            "Vec<u8>"
        );
        assert_eq!(
            fold_type_name(
                "alloc::vec::Vec<alloc::vec::Vec<u8, alloc::alloc::Global>, alloc::alloc::Global>"
            ),
            "Vec<Vec<u8>>"
        );
        // An allocator that is not the closing argument is somebody's
        // real parameter.
        assert_eq!(
            fold_type_name("a::B<u8, alloc::alloc::Global, u16>"),
            "a::B<u8, alloc::alloc::Global, u16>"
        );
    }

    /// The fold is idempotent: what lookups compare folded-to-folded
    /// must not fold further on the second pass.
    #[test]
    fn test_the_fold_is_idempotent() {
        for name in [
            "oximeter_producer::registration_task::{async_fn_env#0}",
            "alloc::vec::Vec<u8, alloc::alloc::Global>",
            "tokio::time::timeout::Timeout<mpsc::recv::{async_fn_env#0}<u32>>",
        ] {
            let once = fold_type_name(name).into_owned();
            assert_eq!(fold_type_name(&once), once, "folding {name:?}");
        }
    }

    #[test]
    fn test_kinds_classify_the_outer_name() {
        assert_eq!(
            coroutine_kind("crate::work::{async_fn_env#0}<T>"),
            Some("async fn")
        );
        assert_eq!(
            coroutine_kind("crate::work::{async_block_env#2}"),
            Some("async block")
        );
        assert_eq!(
            coroutine_kind("crate::work::{async_closure_env#1}"),
            Some("async closure")
        );
        assert_eq!(
            coroutine_kind("core::future::poll_fn::PollFn<crate::work::{async_fn_env#0}>"),
            None
        );
        assert_eq!(coroutine_kind("tokio::time::sleep::Sleep"), None);
    }

    #[test]
    fn test_display_joins_the_kind_to_the_folded_name() {
        assert_eq!(
            display_future_name("futurelock::do_stuff::{async_fn_env#0}"),
            "async fn futurelock::do_stuff"
        );
        assert_eq!(
            display_future_name("tokio::time::sleep::Sleep"),
            "future tokio::time::sleep::Sleep"
        );
    }

    /// What display joined, a lookup strips — and only as the leading
    /// kind word, never inside a name.
    #[test]
    fn test_the_kind_prefix_strips_back_off() {
        assert_eq!(strip_kind_prefix("async fn foo::bar"), "foo::bar");
        assert_eq!(
            strip_kind_prefix("async block foo::{async_block#0}"),
            "foo::{async_block#0}"
        );
        assert_eq!(
            strip_kind_prefix("future tokio::time::Sleep"),
            "tokio::time::Sleep"
        );
        assert_eq!(strip_kind_prefix("foo::bar"), "foo::bar");
        for name in [
            "async fn foo",
            "async block foo",
            "async closure foo",
            "async foo",
            "future foo",
        ] {
            assert_eq!(strip_kind_prefix(name), "foo", "{name:?}");
        }
    }
}
