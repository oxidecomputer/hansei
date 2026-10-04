// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! hyper-util's client pools, read through their bindings: the far end
//! of each pooled HTTP connection, named by the key it was made for.
//!
//! A pool keeps a connection's sender under the key `(Scheme,
//! Authority)` the connection was made for — in its idle map while the
//! connection waits to be checked out, in the `Pooled` whoever checked
//! it out holds. The sender's `want::Giver` shares one `Arc<want::Inner>`
//! with the `Taker` of the receiver the connection's dispatcher reads,
//! so that pointer, read on both sides, says which connection a key
//! belongs to.

use super::bundle::{Context, read_request_text, socket_addr_text};
use super::census::{NodeStop, walk_table_buckets};
use super::observe::{PoolInfo, PoolInfos, PoolPeers, ReadContext};

use anyhow::{Result, anyhow};
use hansei_bundle::{DynStreamCase, HttpPoolBinding, TypedPath};
use proc::Target;
use reify::Value;

/// The most idle connections one key's list is read for: past this a
/// length word did not read as the list's.
const MAX_IDLE_PER_KEY: u64 = 4096;

/// The most buckets one pool's idle map is walked for.
const MAX_KEYS: usize = 4096;

/// The most extras one connection's chain is followed through: each
/// connector layer adds one, and a chain past this did not read as one.
const MAX_EXTRAS: usize = 16;

/// Read the connections the pool value names into `peers`, and what
/// the pool keeps of how each was made into `infos`: a reaper's
/// idle entries, each under its bucket's key, or a checkout's one
/// connection under its own key. A reaper whose pool's strong count is
/// zero names nothing — the pool was dropped, and the map behind it is
/// not the pool's. A connection whose key text or want pointer does not
/// read is left out; a map or list that does not read is an error, with
/// whatever was read before it kept.
pub(crate) fn read_pool<'b, T: Target>(
    ctx: &Context<'b, T>,
    read: &ReadContext<'_>,
    value: Value<'b>,
    binding: &HttpPoolBinding,
    peers: &mut PoolPeers,
    infos: &mut PoolInfos,
) -> Result<()> {
    let at = |root: Value<'b>, path: &TypedPath| -> Option<Value<'b>> {
        let landed = super::contract::execute_steps(ctx, read, root, &path.steps)
            .ok()?
            .optional()?;
        (landed.ty.id() == path.target).then_some(landed)
    };
    let word = |root: Value<'b>, path: &TypedPath| -> Option<u64> {
        at(root, path)?.parse::<u64>(ctx.proc).ok()
    };
    let text = |root: Value<'b>, ptr: &TypedPath, len: &TypedPath| -> Option<String> {
        read_request_text(ctx.proc, word(root, ptr)?, word(root, len)?)
    };
    let info = |root: Value<'b>, path: &Option<TypedPath>| -> Option<PoolInfo> {
        read_connected(ctx, read, at(root, path.as_ref()?)?)
    };
    match binding {
        HttpPoolBinding::Checkout {
            key_ptr,
            key_len,
            want,
            conn_info,
            ..
        } => {
            // A checkout whose `value` is `None` has handed its
            // connection back, and the want route reads inactive.
            if let Some((want, key)) = word(value, want)
                .filter(|want| *want != 0)
                .zip(text(value, key_ptr, key_len))
            {
                peers.0.insert(want, key);
                if let Some(info) = info(value, conn_info) {
                    infos.0.insert(want, info);
                }
            }
            Ok(())
        }
        HttpPoolBinding::Reaper {
            strong,
            idle,
            key_ptr,
            key_len,
            entries_ptr,
            entries_len,
            entry,
            want,
            conn_info,
            ..
        } => {
            let Some(count) = word(value, strong) else {
                return Err(anyhow!(
                    "the pool reaper at {:#x} holds no pool whose count reads",
                    value.addr
                ));
            };
            if count == 0 {
                return Ok(());
            }
            let map = at(value, idle).ok_or_else(|| {
                anyhow!("the pool reaper at {:#x} reaches no idle map", value.addr)
            })?;
            let table = ctx
                .type_semantics(map.ty.id())
                .and_then(|record| record.table.as_ref())
                .ok_or_else(|| anyhow!("the pool's idle map binds no table"))?;
            let entry = ctx
                .view
                .ty(*entry)
                .ok_or_else(|| anyhow!("the tokio info records no idle entry type"))?;
            let stride = entry.size();
            let visit = &mut |_: usize, bucket: Value<'b>| -> std::result::Result<(), NodeStop> {
                let Some(key) = text(bucket, key_ptr, key_len) else {
                    return Ok(());
                };
                let (Some(base), Some(len)) =
                    (word(bucket, entries_ptr), word(bucket, entries_len))
                else {
                    return Ok(());
                };
                let (span, entries) = idle_entries(base, len, stride)?;
                if let Some(refusal) = read.refusal(base, span) {
                    return Err(NodeStop::Refused {
                        what: "pool idle list",
                        addr: base,
                        refusal,
                    });
                }
                for addr in entries {
                    let Ok(idle) = Value::read(ctx.proc, entry, addr) else {
                        continue;
                    };
                    if let Some(want) = word(idle, want).filter(|want| *want != 0) {
                        peers.0.insert(want, key.clone());
                        if let Some(info) = info(idle, conn_info) {
                            infos.0.insert(want, info);
                        }
                    }
                }
                Ok(())
            };
            walk_table_buckets(ctx, read, map, table, MAX_KEYS, visit)
                .map(|_| ())
                .map_err(|stop| {
                    anyhow::Error::from(stop).context(format!(
                        "the pool reaper at {:#x} lists only part of its idle map",
                        value.addr
                    ))
                })
        }
    }
}

/// What a pooled connection's `Connected` says, through the binding its
/// type's record carries: the ALPN enum's enumerator, the proxy flag's
/// byte, and the socket's two addresses, which the connector's
/// `HttpInfo` keeps among the extras — each extra named by the symbol
/// its vtable's `set` slot holds, a chain's own value tried before the
/// extras it wraps. `None` where the type binds no info; a word that
/// does not read is left out on its own.
fn read_connected<'b, T: Target>(
    ctx: &Context<'b, T>,
    read: &ReadContext<'_>,
    connected: Value<'b>,
) -> Option<PoolInfo> {
    let binding = ctx.type_semantics(connected.ty.id())?.connected.as_ref()?;
    let at = |root: Value<'b>, path: &TypedPath| -> Option<Value<'b>> {
        let landed = super::contract::execute_steps(ctx, read, root, &path.steps)
            .ok()?
            .optional()?;
        (landed.ty.id() == path.target).then_some(landed)
    };
    let mut info = PoolInfo {
        h2: at(connected, &binding.alpn)
            .and_then(|alpn| alpn.ty.enumerator_name(alpn.bytes))
            .map(|name| name == "H2"),
        proxied: at(connected, &binding.is_proxied)
            .and_then(|flag| flag.bytes.first().copied())
            .map(|byte| byte != 0),
        ..PoolInfo::default()
    };
    let cases: Vec<DynStreamCase> = binding
        .cases
        .iter()
        .map(|case| DynStreamCase {
            symbol: case.symbol,
            target: case.target,
        })
        .collect();
    // The extras the connector recorded, latest first: an extra without
    // the addresses hands on to the one it wraps.
    let (mut holder, mut pointer) = (connected, &binding.extra);
    for _ in 0..MAX_EXTRAS {
        let Ok(extra) = ctx.dyn_stream(holder, pointer, &binding.layout, &cases, read) else {
            break;
        };
        let Some(case) = binding.cases.iter().find(|c| c.target == extra.ty.id()) else {
            break;
        };
        if let (Some(remote), Some(local)) = (&case.remote_addr, &case.local_addr) {
            info.remote = at(extra, remote).and_then(socket_addr_text);
            info.local = at(extra, local).and_then(socket_addr_text);
            break;
        }
        match &case.next {
            Some(next) => (holder, pointer) = (extra, next),
            None => break,
        }
    }
    Some(info)
}

/// An idle list of `len` entries `stride` bytes apart from `base`: the
/// bytes it spans and each entry's address. A length past the cap, or
/// an entry type of no size, says the words did not read as a list's.
fn idle_entries(
    base: u64,
    len: u64,
    stride: u64,
) -> std::result::Result<(u64, impl Iterator<Item = u64>), NodeStop> {
    if len > MAX_IDLE_PER_KEY || stride == 0 {
        return Err(NodeStop::Capped {
            unit: "idle connections",
            max: MAX_IDLE_PER_KEY as usize,
        });
    }
    Ok((
        len * stride,
        (0..len).map(move |index| base + index * stride),
    ))
}

#[cfg(test)]
mod tests {
    use super::{MAX_IDLE_PER_KEY, idle_entries};
    use crate::testkit::{self, fixture_sets};
    use crate::tokio::census::{NodeStop, census};

    /// An idle list's entries sit `stride` apart from its base, and the
    /// refusal is asked about all of them at once; a length past the
    /// cap, or an entry of no size, stops the list unread.
    #[test]
    fn test_an_idle_list_is_read_entry_by_entry_up_to_the_cap() {
        let (span, entries) = idle_entries(0x1000, 3, 0x40).unwrap();
        assert_eq!(span, 0xc0);
        assert_eq!(entries.collect::<Vec<_>>(), [0x1000, 0x1040, 0x1080]);
        let (span, entries) = idle_entries(0x1000, MAX_IDLE_PER_KEY, 0x40).unwrap();
        assert_eq!(span, MAX_IDLE_PER_KEY * 0x40);
        assert_eq!(entries.count() as u64, MAX_IDLE_PER_KEY);
        for (len, stride) in [(MAX_IDLE_PER_KEY + 1, 0x40), (1, 0)] {
            assert!(
                matches!(
                    idle_entries(0x1000, len, stride),
                    Err(NodeStop::Capped { max, .. }) if max as u64 == MAX_IDLE_PER_KEY
                ),
                "{len} entries of {stride} bytes"
            );
        }
    }

    /// Over the fixture that holds connections, on every system that
    /// captures it, the census names three pooled connections, all under
    /// the listener's loopback authority: the one the reaped client's
    /// pool keeps idle, read through its reaper, and the two checked out
    /// for the parked GETs, read off the `Pooled` each caller's chain
    /// holds under its client's response future — the hyper-util
    /// requester's and reqwest's. The client whose pool keeps no reaper
    /// and has nothing checked out is named by nothing.
    #[test]
    fn test_the_census_names_idle_and_checked_out_connections() {
        for set in fixture_sets() {
            let (bundle, core) = testkit::load(set, "http-conns");
            let ctx = testkit::context(&bundle, &core);
            let list = testkit::tasks(&ctx, &core);
            let census = census(&ctx, &list);
            let peers = &census.pool_peers.0;
            assert_eq!(peers.len(), 3, "{set}: {peers:?}");
            let authorities: std::collections::BTreeSet<&str> =
                peers.values().map(String::as_str).collect();
            let [authority] = authorities.into_iter().collect::<Vec<_>>()[..] else {
                panic!("{set}: {peers:?}");
            };
            let port = authority
                .strip_prefix("127.0.0.1:")
                .unwrap_or_else(|| panic!("{set}: {authority}"));
            assert!(port.parse::<u16>().is_ok(), "{set}: {authority}");
            for want in peers.keys() {
                assert_ne!(*want, 0, "{set}");
                assert_eq!(census.pool_peers.authority(*want), Some(authority));
            }
        }
    }

    /// The same three connections' info, as each pool keeps it beside
    /// the sender: HTTP/1 over no proxy, and the connector's record of
    /// the socket — the listener's address, which the key names, and a
    /// loopback address of the client's own on another port. Every one
    /// reads, whichever of the extras' two shapes the connector built.
    #[test]
    fn test_the_census_reads_each_pooled_connections_info() {
        for set in fixture_sets() {
            let (bundle, core) = testkit::load(set, "http-conns");
            let ctx = testkit::context(&bundle, &core);
            let list = testkit::tasks(&ctx, &core);
            let census = census(&ctx, &list);
            let infos = &census.pool_infos.0;
            assert_eq!(
                infos.keys().collect::<std::collections::BTreeSet<_>>(),
                census
                    .pool_peers
                    .0
                    .keys()
                    .collect::<std::collections::BTreeSet<_>>(),
                "{set}: {infos:?}"
            );
            for (want, info) in infos {
                let authority = census.pool_peers.authority(*want);
                assert_eq!(info.h2, Some(false), "{set}: {info:?}");
                assert_eq!(info.proxied, Some(false), "{set}: {info:?}");
                assert_eq!(info.remote.as_deref(), authority, "{set}: {info:?}");
                let local = info
                    .local
                    .as_deref()
                    .unwrap_or_else(|| panic!("{set}: {info:?}"));
                assert!(local.starts_with("127.0.0.1:"), "{set}: {info:?}");
                assert_ne!(Some(local), authority, "{set}: {info:?}");
            }
        }
    }
}
