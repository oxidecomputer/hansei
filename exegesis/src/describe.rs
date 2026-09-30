// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Render a [`DisplayNode`] as text: every selector resolved to its
//! field-name chain *and* byte offset, rooted the way resolution roots it.
//!
//! One renderer serves two readers. `hansei tokio-info dump` prints it so an operator
//! can see what a formatter actually addresses in a given binary, and the
//! golden tests assert on it, where resolving to names and offsets is what
//! catches a detector that fires but navigates to the wrong member. Those two
//! must not drift: the summary a test pins is the summary a person reads.
//!
//! Type *ids* are not portable across platforms, so everything here keys on
//! names. Nothing panics on a malformed bundle — a bad id or a path that leaves
//! the type graph prints a marker in place of the datum, since this now runs
//! over whatever a bundle file happens to contain.

use hansei_bundle::{
    Bundle, BundleTypeId, DisplayNode, Field, MapEntries, MemberDef, MemberRef, Selector, Step,
    Stmt, TypeDef, ValueExpr,
};

/// Render the debug format attached to `id` as `<type> :: Node <program>`.
pub fn describe_debug_format(bundle: &Bundle, id: BundleTypeId, node: &DisplayNode) -> String {
    format!(
        "{} :: Node {}",
        fq_name(bundle, id),
        describe_node(bundle, id, node)
    )
}

/// The definition of a type, or `None` when the id is out of range.
fn type_def(bundle: &Bundle, id: BundleTypeId) -> Option<&TypeDef> {
    bundle.types.types.get(id.0 as usize)
}

/// The members of an aggregate, or `None` for anything else.
fn members_of(bundle: &Bundle, id: BundleTypeId) -> Option<&[MemberDef]> {
    match type_def(bundle, id)? {
        TypeDef::Struct { members, .. } | TypeDef::Union { members, .. } => Some(members),
        _ => None,
    }
}

/// The fully-qualified name of a type, or a placeholder for the anonymous
/// pointer/array kinds.
fn fq_name(bundle: &Bundle, id: BundleTypeId) -> String {
    let s = |r| bundle.strings.get(r).unwrap_or("<bad strref>").to_owned();
    match type_def(bundle, id) {
        Some(
            TypeDef::Base { name, .. }
            | TypeDef::Struct { name, .. }
            | TypeDef::Union { name, .. }
            | TypeDef::Enum { name, .. }
            | TypeDef::CEnum { name, .. }
            | TypeDef::Opaque { name, .. },
        ) => s(*name),
        Some(TypeDef::Pointer { .. }) => "<pointer>".to_owned(),
        Some(TypeDef::Array { .. }) => "<array>".to_owned(),
        None => format!("<bad type id {}>", id.0),
    }
}

/// The member a [`MemberRef`] addresses, resolved the same way the bundle
/// resolves it.
fn member_at<'m>(members: &'m [MemberDef], at: &MemberRef) -> Option<&'m MemberDef> {
    let index = at.resolve(members.len(), |index, name| members[index].name == name)?;
    members.get(index)
}

/// How an unresolvable member address prints in the summary.
fn unresolved(bundle: &Bundle, at: &MemberRef) -> String {
    match at {
        MemberRef::Index(index) => format!("<oob:{index}>"),
        MemberRef::Named(name) => {
            let name = bundle.strings.get(*name).unwrap_or("<bad strref>");
            format!("<no unique member `{name}`>")
        }
    }
}

/// Walk selector steps from `root`, returning one `(dotted field-name chain,
/// terminal byte offset, landed type)` per path the steps can take: exactly
/// one for the selectors (nearly all) that cross no [`Step::ActiveVariant`],
/// and one per variant — each chain naming its variant the way a named
/// variant hop reads — where a value-expression read crosses one, since
/// every variant's continuation is part of what the program addresses. This
/// is the portable, layout-sensitive rendering of a path: a wrong member
/// changes the name or the offset even when the path still validates.
fn walk_all(
    bundle: &Bundle,
    root: BundleTypeId,
    steps: &[Step],
    names: Vec<String>,
    start: u64,
) -> Vec<(String, u64, BundleTypeId)> {
    let s = |r| bundle.strings.get(r).unwrap_or("<bad strref>").to_owned();
    let mut names = names;
    let mut offset = start;
    let mut cur = root;
    for (index, step) in steps.iter().enumerate() {
        match step {
            Step::Member(at) => {
                let Some(members) = members_of(bundle, cur) else {
                    names.push("<non-aggregate>".to_owned());
                    return vec![(names.join("."), offset, cur)];
                };
                match member_at(members, at) {
                    Some(m) => {
                        // A positional hop is marked, so an assertion pins not
                        // only where a path lands but how it says to get there.
                        // `%` is the marker because it cannot occur in a Rust
                        // type name, unlike `#`, which every closure and async
                        // block carries.
                        names.push(match at {
                            MemberRef::Named(_) => s(m.name),
                            MemberRef::Index(index) => format!("{}%{index}", s(m.name)),
                        });
                        offset += m.offset;
                        cur = m.ty;
                    }
                    None => {
                        names.push(unresolved(bundle, at));
                        return vec![(names.join("."), offset, cur)];
                    }
                }
            }
            Step::Deref => match type_def(bundle, cur) {
                Some(TypeDef::Pointer { target, .. }) => {
                    names.push("*".to_owned());
                    offset = 0;
                    cur = *target;
                }
                _ => {
                    names.push("<non-pointer-deref>".to_owned());
                    return vec![(names.join("."), offset, cur)];
                }
            },
            Step::Variant(name) => {
                let variant = match type_def(bundle, cur) {
                    Some(TypeDef::Enum { shape, .. }) => {
                        let mut matches = shape.variants.iter().filter(|v| v.name == *name);
                        match (matches.next(), matches.next()) {
                            (Some(variant), None) => Some(variant),
                            _ => None,
                        }
                    }
                    _ => None,
                };
                match variant {
                    // Braced, so a variant hop reads apart from the member
                    // names around it; braces cannot occur in a member name.
                    Some(v) => {
                        names.push(format!("{{{}}}", s(v.name)));
                        offset += v.payload.offset;
                        cur = v.payload.ty;
                    }
                    None => {
                        let name = bundle.strings.get(*name).unwrap_or("<bad strref>");
                        names.push(format!("<no unique variant `{name}`>"));
                        return vec![(names.join("."), offset, cur)];
                    }
                }
            }
            Step::ActiveVariant => {
                // Which variant continues is a runtime fact, so every one is
                // a path of its own, spelled like a named variant hop.
                let Some(TypeDef::Enum { shape, .. }) = type_def(bundle, cur) else {
                    names.push("<active variant of a non-enum>".to_owned());
                    return vec![(names.join("."), offset, cur)];
                };
                let rest = &steps[index + 1..];
                let mut out = Vec::new();
                for v in &shape.variants {
                    let mut branch = names.clone();
                    branch.push(format!("{{{}}}", s(v.name)));
                    out.extend(walk_all(
                        bundle,
                        v.payload.ty,
                        rest,
                        branch,
                        offset + v.payload.offset,
                    ));
                }
                if out.is_empty() {
                    names.push("<active variant of an empty enum>".to_owned());
                    return vec![(names.join("."), offset, cur)];
                }
                return out;
            }
        }
    }
    vec![(names.join("."), offset, cur)]
}

/// Walk a selector from `root` to the one place it addresses. The adapter for
/// the callers that need a single landing — the selectors they resolve may
/// not cross a [`Step::ActiveVariant`], so the first path is the only one.
fn walk(bundle: &Bundle, root: BundleTypeId, sel: &Selector) -> (String, u64, BundleTypeId) {
    walk_all(bundle, root, sel.steps(), Vec::new(), 0)
        .into_iter()
        .next()
        .expect("walk_all returns at least one path")
}

/// Render one path as `chain@+offset` (rooted at `root`), with the paths of a
/// fanning selector joined as `chain@+offset | chain@+offset`.
fn field(bundle: &Bundle, root: BundleTypeId, sel: &Selector) -> String {
    walk_all(bundle, root, sel.steps(), Vec::new(), 0)
        .into_iter()
        .map(|(chain, offset, _)| {
            let chain = if chain.is_empty() {
                "<self>".to_owned()
            } else {
                chain
            };
            format!("{chain}@+{offset}")
        })
        .collect::<Vec<_>>()
        .join(" | ")
}

fn ptr_target(bundle: &Bundle, id: BundleTypeId) -> Option<BundleTypeId> {
    match type_def(bundle, id)? {
        TypeDef::Pointer { target, .. } => Some(*target),
        _ => None,
    }
}

/// The payload type of an enum's `Some` variant (BTreeMap's `root` is an
/// `Option<Box<…>>`).
fn some_payload(bundle: &Bundle, id: BundleTypeId) -> Option<BundleTypeId> {
    match type_def(bundle, id)? {
        TypeDef::Enum { shape, .. } => shape
            .variants
            .iter()
            .find(|v| bundle.strings.get(v.name) == Some("Some"))
            .map(|v| v.payload.ty),
        _ => None,
    }
}

fn array_elem(bundle: &Bundle, id: BundleTypeId) -> Option<BundleTypeId> {
    match type_def(bundle, id)? {
        TypeDef::Array { elem, .. } => Some(*elem),
        _ => None,
    }
}

/// A B-tree map's entry walk, each selector resolved against the node type
/// the walk had reached when it reads it.
fn describe_btree_entries(bundle: &Bundle, root: BundleTypeId, entries: &MapEntries) -> String {
    let MapEntries::BTree {
        root: map_root,
        root_node,
        height,
        node,
        leaf,
        leaf_len,
        leaf_keys,
        leaf_values,
        internal,
        internal_data,
        internal_edges,
        edge,
    } = entries
    else {
        return String::new();
    };
    let (_, _, root_ty) = walk(bundle, root, map_root);
    let some = some_payload(bundle, root_ty).unwrap_or(root_ty);
    let (_, _, node_ref) = walk(bundle, some, root_node);
    let (_, _, edges_ty) = walk(bundle, *internal, internal_edges);
    let edge_elem = array_elem(bundle, edges_ty).unwrap_or(*internal);
    format!(
        "BTree {{ root={}, root_node={}, height={}, node={}, leaf={}, leaf_len={}, \
         leaf_keys={}, leaf_values={}, internal={}, internal_data={}, internal_edges={}, \
         edge={} }}",
        field(bundle, root, map_root),
        field(bundle, some, root_node),
        field(bundle, node_ref, height),
        field(bundle, node_ref, node),
        fq_name(bundle, *leaf),
        field(bundle, *leaf, leaf_len),
        field(bundle, *leaf, leaf_keys),
        field(bundle, *leaf, leaf_values),
        fq_name(bundle, *internal),
        field(bundle, *internal, internal_data),
        field(bundle, *internal, internal_edges),
        field(bundle, edge_elem, edge),
    )
}

/// Render a [`DisplayNode`] tree, resolving every selector against the type it
/// is rooted at — the enclosing value for most, a list's node type, a pointer's
/// pointee, or whichever storage type a map's walk had reached.
pub fn describe_node(bundle: &Bundle, root: BundleTypeId, node: &DisplayNode) -> String {
    match node {
        DisplayNode::Scalar { at, .. } => field(bundle, root, at),
        DisplayNode::Computed { value, .. } => {
            format!("Computed({})", describe_value_expr(bundle, root, value))
        }
        DisplayNode::Symbol { at } => format!("Symbol {{ {} }}", field(bundle, root, at)),
        DisplayNode::Struct { fields } => {
            let parts: Vec<String> = fields
                .iter()
                .map(|fld| describe_field(bundle, root, fld))
                .collect();
            format!("Struct {{ {} }}", parts.join(", "))
        }
        DisplayNode::List {
            head,
            next,
            node,
            node_ty,
        } => format!(
            "List {{ head={}, node_ty={}, next={}, {} }}",
            field(bundle, root, head),
            fq_name(bundle, *node_ty),
            field(bundle, *node_ty, next),
            describe_node(bundle, *node_ty, node),
        ),
        DisplayNode::Str {
            pointer,
            length,
            capacity,
            nul_terminated,
            offset,
        } => {
            let capacity = match capacity {
                Some(capacity) => format!(", capacity={}", field(bundle, root, capacity)),
                None => String::new(),
            };
            let nul = match nul_terminated {
                true => ", nul_terminated",
                false => "",
            };
            let offset = match offset {
                0 => String::new(),
                offset => format!(", offset=+{offset:#x}"),
            };
            format!(
                "Str {{ pointer={}, length={}{}{}{} }}",
                field(bundle, root, pointer),
                field(bundle, root, length),
                capacity,
                nul,
                offset,
            )
        }
        DisplayNode::Slice {
            pointer,
            length,
            capacity,
            element,
        } => {
            let capacity = match capacity {
                Some(capacity) => format!(", capacity={}", field(bundle, root, capacity)),
                None => String::new(),
            };
            format!(
                "Slice {{ pointer={}, length={}{}, element={} }}",
                field(bundle, root, pointer),
                field(bundle, root, length),
                capacity,
                fq_name(bundle, *element),
            )
        }
        DisplayNode::Bytes { at, notation } => {
            format!("Bytes {notation:?} {{ {} }}", field(bundle, root, at))
        }
        DisplayNode::SocketAddr { ip, port, scope_id } => {
            let scope = match scope_id {
                Some(scope_id) => format!(", scope_id={}", field(bundle, root, scope_id)),
                None => String::new(),
            };
            format!(
                "SocketAddr {{ ip={}, port={}{scope} }}",
                field(bundle, root, ip),
                field(bundle, root, port)
            )
        }
        DisplayNode::Alias {
            at,
            follow_pointers,
        } => {
            let follow = if *follow_pointers { ", follow" } else { "" };
            format!("Alias {{ {}{} }}", field(bundle, root, at), follow)
        }
        DisplayNode::SlotCount { bitmap, slots } => format!(
            "SlotCount {{ bitmap={}, slots={} }}",
            field(bundle, root, bitmap),
            field(bundle, root, slots),
        ),
        DisplayNode::Pointer { at, via, then } => {
            let (_, _, ptr_land) = walk(bundle, root, at);
            let pointee = ptr_target(bundle, ptr_land).unwrap_or(root);
            let (_, _, target) = walk(bundle, pointee, via);
            format!(
                "Pointer {{ at={}, pointee={}, via={}, then={} }}",
                field(bundle, root, at),
                fq_name(bundle, pointee),
                field(bundle, pointee, via),
                describe_node(bundle, target, then),
            )
        }
        DisplayNode::DynPointer {
            pointer,
            vtable,
            drop_in_place,
            size,
            align,
            tail_prefixes,
        } => format!(
            "DynPointer {{ pointer={}, vtable={}, slots=[drop_in_place:{drop_in_place}, size:{size}, align:{align}], tail_prefixes={tail_prefixes:?} }}",
            field(bundle, root, pointer),
            field(bundle, root, vtable),
        ),
        DisplayNode::Map {
            length,
            key,
            value,
            entries,
        } => {
            let value = match value {
                Some(value) => fq_name(bundle, *value),
                None => "<set>".to_string(),
            };
            let entries = match entries.as_ref() {
                MapEntries::BTree { .. } => describe_btree_entries(bundle, root, entries),
                MapEntries::Hash {
                    bucket_mask,
                    ctrl,
                    bucket,
                    key: key_at,
                    value: value_at,
                } => format!(
                    "Hash {{ bucket_mask={}, ctrl={}, bucket={}, key={}{} }}",
                    field(bundle, root, bucket_mask),
                    field(bundle, root, ctrl),
                    fq_name(bundle, *bucket),
                    field(bundle, *bucket, key_at),
                    match value_at {
                        Some(value_at) => format!(", value={}", field(bundle, *bucket, value_at)),
                        None => String::new(),
                    },
                ),
            };
            format!(
                "Map {{ length={}, key={}, value={value}, entries={entries} }}",
                field(bundle, root, length),
                fq_name(bundle, *key),
            )
        }
        DisplayNode::Variant {
            discriminant,
            arms,
            default,
        } => {
            let arms = arms
                .iter()
                .map(|arm| {
                    let label = arm
                        .label
                        .map_or("", |l| bundle.strings.get(l).unwrap_or("?"));
                    match &arm.payload {
                        Some(payload) => format!(
                            "{}=>{label}({})",
                            arm.value,
                            describe_node(bundle, root, payload)
                        ),
                        None => format!("{}=>{label}", arm.value),
                    }
                })
                .collect::<Vec<_>>()
                .join(", ");
            let default = match default {
                Some(node) => format!(", default={}", describe_node(bundle, root, node)),
                None => String::new(),
            };
            format!(
                "Variant {{ discr={}, arms=[{arms}]{default} }}",
                describe_value_expr(bundle, root, discriminant),
            )
        }
        DisplayNode::CustomList {
            vars,
            condition,
            body,
            element,
        } => {
            let vars = vars
                .iter()
                .map(|expr| describe_value_expr(bundle, root, expr))
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "CustomList {{ vars=[{vars}], condition={}, body={}, element={} }}",
                describe_value_expr(bundle, root, condition),
                describe_stmts(bundle, root, body),
                fq_name(bundle, *element),
            )
        }
    }
}

/// Render a [`ValueExpr`], resolving each `Read` selector to its member path
/// (crossing any `Deref` via [`walk`]).
fn describe_value_expr(bundle: &Bundle, root: BundleTypeId, expr: &ValueExpr) -> String {
    match expr {
        ValueExpr::Read(sel) => format!("Read({})", field(bundle, root, sel)),
        ValueExpr::Const(value) => format!("{value:#x}"),
        ValueExpr::And(a, b) => format!(
            "({} & {})",
            describe_value_expr(bundle, root, a),
            describe_value_expr(bundle, root, b)
        ),
        ValueExpr::Not(inner) => format!("~{}", describe_value_expr(bundle, root, inner)),
        ValueExpr::Ne(a, b) => format!(
            "({} != {})",
            describe_value_expr(bundle, root, a),
            describe_value_expr(bundle, root, b)
        ),
        ValueExpr::Var(id) => format!("Var({id})"),
        ValueExpr::Load { addr, size } => {
            format!("Load({}, {size})", describe_value_expr(bundle, root, addr))
        }
        ValueExpr::Add(a, b) => format!(
            "({} + {})",
            describe_value_expr(bundle, root, a),
            describe_value_expr(bundle, root, b)
        ),
        ValueExpr::Sub(a, b) => format!(
            "({} - {})",
            describe_value_expr(bundle, root, a),
            describe_value_expr(bundle, root, b)
        ),
        ValueExpr::Mul(a, b) => format!(
            "({} * {})",
            describe_value_expr(bundle, root, a),
            describe_value_expr(bundle, root, b)
        ),
        ValueExpr::Lt(a, b) => format!(
            "({} < {})",
            describe_value_expr(bundle, root, a),
            describe_value_expr(bundle, root, b)
        ),
        ValueExpr::Shl(a, b) => format!(
            "({} << {})",
            describe_value_expr(bundle, root, a),
            describe_value_expr(bundle, root, b)
        ),
    }
}

/// Render a statement sequence as `[stmt; stmt]`.
///
/// The body is printed in full rather than counted: every address a program
/// emits at, and every offset it walks by, lives in these statements, so a
/// count would hide exactly the drift this summary exists to catch.
fn describe_stmts(bundle: &Bundle, root: BundleTypeId, stmts: &[Stmt]) -> String {
    let parts: Vec<String> = stmts
        .iter()
        .map(|stmt| describe_stmt(bundle, root, stmt))
        .collect();
    format!("[{}]", parts.join("; "))
}

/// A branch of an [`Stmt::If`], braced so a nested sequence reads as a block
/// rather than as another list of statements.
fn describe_block(bundle: &Bundle, root: BundleTypeId, stmts: &[Stmt]) -> String {
    let parts: Vec<String> = stmts
        .iter()
        .map(|stmt| describe_stmt(bundle, root, stmt))
        .collect();
    format!("{{ {} }}", parts.join("; "))
}

fn describe_stmt(bundle: &Bundle, root: BundleTypeId, stmt: &Stmt) -> String {
    match stmt {
        Stmt::Set { var, value } => {
            format!("Var({var}) = {}", describe_value_expr(bundle, root, value))
        }
        Stmt::If {
            cond,
            then,
            otherwise,
        } => {
            let otherwise = if otherwise.is_empty() {
                String::new()
            } else {
                format!(" else {}", describe_block(bundle, root, otherwise))
            };
            format!(
                "if {} {}{otherwise}",
                describe_value_expr(bundle, root, cond),
                describe_block(bundle, root, then),
            )
        }
        Stmt::Emit { at } => format!("emit({})", describe_value_expr(bundle, root, at)),
        Stmt::Break { cond } => format!("break if {}", describe_value_expr(bundle, root, cond)),
    }
}

/// Render one [`Field`] of a [`DisplayNode::Struct`].
fn describe_field(bundle: &Bundle, root: BundleTypeId, fld: &Field) -> String {
    let member_name = |at: &MemberRef| match members_of(bundle, root) {
        Some(members) => {
            member_at(members, at).map_or("?", |m| bundle.strings.get(m.name).unwrap_or("?"))
        }
        None => "?",
    };
    match fld {
        Field::Member { at, node: None } => format!("{}: <structural>", member_name(at)),
        Field::Member {
            at,
            node: Some(node),
        } => format!("{}: {}", member_name(at), describe_node(bundle, root, node)),
        Field::Synth { label, node } => {
            format!(
                "{}: {}",
                bundle.strings.get(*label).unwrap_or("?"),
                describe_node(bundle, root, node)
            )
        }
    }
}

/// Render the bundle's semantic table as text, one line per fact, keyed
/// on type names so the same text serves `tokio-info dump`, the matrix
/// catalog and a golden assertion alike. Origins and rules come first,
/// numbered as the records refer to them; then every record in type
/// order; then each task entry's scheduler class.
pub fn describe_semantics(bundle: &Bundle) -> String {
    use hansei_bundle::{
        Continuation, CoroutineState, FutureEvidence, FutureTarget, HttpPoolBinding,
        IoRouteBinding, IoRouteStep, PollAction, PollProgram, SemanticIssue, SemanticOrigin,
        StoragePolicy,
    };
    use std::fmt::Write;

    let s = |r| bundle.strings.get(r).unwrap_or("<bad strref>");
    let type_name = |id: BundleTypeId| -> String {
        bundle
            .types
            .name_index
            .iter()
            .find(|&&(_, ty)| ty == id)
            .map(|&(name, _)| s(name).to_owned())
            .unwrap_or_else(|| format!("[{}]", id.0))
    };
    let issue = |i: &SemanticIssue| match i.detail {
        Some(detail) => format!("{:?}: {}", i.kind, s(detail)),
        None => format!("{:?}", i.kind),
    };
    let path = |root: BundleTypeId, p: &hansei_bundle::TypedPath| {
        format!(
            "{} -> {}",
            field(bundle, root, &Selector(p.steps.clone())),
            type_name(p.target)
        )
    };
    let action = |root: BundleTypeId, a: &PollAction| match a {
        PollAction::Delegate { target, exclusive } => {
            let target = match target {
                FutureTarget::Value(p) => path(root, p),
                FutureTarget::Dynamic { pointer, .. } => format!("dyn {}", path(root, pointer)),
            };
            format!(
                "delegate{} {target}",
                if *exclusive { " (exclusive)" } else { "" }
            )
        }
        PollAction::Primitive => "primitive".to_owned(),
        PollAction::Unresumed => "unresumed".to_owned(),
        PollAction::Returned => "returned".to_owned(),
        PollAction::Panicked => "panicked".to_owned(),
        PollAction::NeverReady => "never ready".to_owned(),
        PollAction::Unknown(i) => format!("unknown ({})", issue(i)),
    };
    let state = |st: &CoroutineState| {
        format!(
            "{}:{:?}[{}]({})",
            s(st.variant),
            st.stage,
            st.locals
                .iter()
                .map(|&n| s(n))
                .collect::<Vec<_>>()
                .join(","),
            st.uncertain_locals
                .iter()
                .map(|&n| s(n))
                .collect::<Vec<_>>()
                .join(",")
        )
    };

    let mut out = String::new();
    let table = &bundle.semantics;
    for (i, origin) in table.origins.iter().enumerate() {
        let text = match origin {
            SemanticOrigin::Rustc { producer, family } => {
                format!("rustc {} ({})", s(*family), s(*producer))
            }
            SemanticOrigin::LibraryLayout {
                package,
                version,
                family,
                selection,
            } => format!(
                "layout {} {} family {} ({selection:?})",
                s(*package),
                version.map(s).unwrap_or("<no version>"),
                s(*family)
            ),
            SemanticOrigin::LibraryDelegation {
                package,
                version,
                family,
                source,
                files,
            } => format!(
                "delegation {} {} family {} from {} ({} checksummed files)",
                s(*package),
                s(*version),
                s(*family),
                s(*source),
                files.len()
            ),
            SemanticOrigin::GitDelegation {
                package,
                repository,
                revision,
                family,
                source,
                files,
            } => format!(
                "git delegation {} {}@{} family {} from {} ({} checksummed files)",
                s(*package),
                s(*repository),
                s(*revision),
                s(*family),
                s(*source),
                files.len()
            ),
        };
        let _ = writeln!(out, "origin {i}: {text}");
    }
    for (i, rule) in table.rules.iter().enumerate() {
        let _ = writeln!(
            out,
            "rule {i}: {:?} rev {} origin {}",
            rule.kind, rule.revision, rule.origin.0
        );
    }
    for record in &table.types {
        let mut line = format!("{} ::", type_name(record.ty));
        match &record.storage {
            StoragePolicy::DeclaredMembers => line.push_str(" members"),
            StoragePolicy::CoroutineStates => line.push_str(" states"),
            StoragePolicy::Unavailable(i) => {
                let _ = write!(line, " unavailable ({})", issue(i));
            }
        }
        if let Some(facts) = &record.future {
            let evidence: Vec<String> = facts
                .evidence
                .iter()
                .map(|e| match e {
                    FutureEvidence::TaskEntry(id) => format!("task {}", id.0),
                    FutureEvidence::PollSymbol(_) => "poll".to_owned(),
                    FutureEvidence::Coroutine(rule) => format!("coroutine rule {}", rule.0),
                    FutureEvidence::DelegatedBy { parent } => {
                        format!("delegated by {}", type_name(*parent))
                    }
                })
                .collect();
            let _ = write!(line, " future[{}]", evidence.join(", "));
            match &facts.continuation {
                Continuation::Unknown(i) => {
                    let _ = write!(line, " continuation unknown ({})", issue(i));
                }
                Continuation::Bound { rule, program } => {
                    let _ = write!(line, " continuation rule {}", rule.0);
                    match program {
                        PollProgram::Direct(a) => {
                            let _ = write!(line, " {}", action(record.ty, a));
                        }
                        PollProgram::MatchVariant { state: st, cases } => {
                            let _ = write!(line, " match {}", path(record.ty, st));
                            for case in cases {
                                let _ = write!(
                                    line,
                                    " {{{}: {}}}",
                                    s(case.variant),
                                    action(record.ty, &case.action)
                                );
                            }
                        }
                    }
                }
            }
        }
        if let Some(layout) = &record.coroutine {
            let states: Vec<String> = layout.states.iter().map(state).collect();
            let _ = write!(
                line,
                " coroutine rule {} {{{}}}",
                layout.rule.0,
                states.join(" ")
            );
        }
        if let Some(access) = &record.access {
            let target = match &access.target {
                FutureTarget::Value(p) => path(record.ty, p),
                FutureTarget::Dynamic { pointer, .. } => {
                    format!("dyn {}", path(record.ty, pointer))
                }
            };
            let _ = write!(
                line,
                " access {:?} rule {} {target}",
                access.kind, access.rule.0
            );
        }
        if let Some(resource) = &record.resource {
            let _ = write!(
                line,
                " resource {:?} rule {}{}{}",
                resource.kind,
                resource.rule.0,
                resource
                    .state_rule
                    .map(|r| format!(" state rule {}", r.0))
                    .unwrap_or_default(),
                if resource.exclusive_pending {
                    " exclusive-pending"
                } else {
                    ""
                }
            );
        }
        if let Some(io) = &record.io {
            let _ = write!(
                line,
                " io rule {} stream {}{}",
                io.rule.0,
                path(record.ty, &io.stream),
                io.remaining
                    .as_ref()
                    .map(|remaining| format!(" remaining {}", path(record.ty, remaining)))
                    .unwrap_or_default()
            );
        }
        match &record.io_route {
            Some(IoRouteBinding {
                rule,
                step: IoRouteStep::Forward { inner },
            }) => {
                let _ = write!(
                    line,
                    " io-route rule {} forward {} to {}",
                    rule.0,
                    path(record.ty, inner),
                    fq_name(bundle, inner.target)
                );
            }
            Some(IoRouteBinding {
                rule,
                step: IoRouteStep::Match { cases },
            }) => {
                let cases: Vec<String> = cases
                    .iter()
                    .map(|case| {
                        format!(
                            "{} to {}",
                            path(record.ty, case),
                            fq_name(bundle, case.target)
                        )
                    })
                    .collect();
                let _ = write!(
                    line,
                    " io-route rule {} match {}",
                    rule.0,
                    cases.join(" | ")
                );
            }
            Some(IoRouteBinding {
                rule,
                step: IoRouteStep::Socket(socket),
            }) => {
                let _ = write!(line, " io-route rule {} socket {socket:?}", rule.0);
            }
            None => {}
        }
        if let Some(container) = &record.container {
            let _ = write!(
                line,
                " container {:?} rule {}",
                container.kind, container.rule.0
            );
        }
        if let Some(request) = &record.request {
            let _ = write!(
                line,
                " request {:?} rule {} method {} text {}",
                request.target,
                request.rule.0,
                path(record.ty, &request.method),
                path(record.ty, &request.target_ptr)
            );
        }
        match &record.pool {
            // The key and the list are read from a bucket of the idle
            // map, the sender from an element of the list: each route is
            // named from its own root.
            Some(HttpPoolBinding::Reaper {
                rule,
                strong,
                idle,
                key_ptr,
                entries_ptr,
                entry,
                want,
                ..
            }) => {
                let bucket = bundle
                    .semantics
                    .types
                    .iter()
                    .find(|r| r.ty == idle.target)
                    .and_then(|r| r.table.as_ref())
                    .map(|table| table.bucket);
                let from_bucket = |p| match bucket {
                    Some(bucket) => path(bucket, p),
                    None => "<no table>".to_owned(),
                };
                let _ = write!(
                    line,
                    " pool reaper rule {} strong {} idle {} key {} entries {} entry {} want {}",
                    rule.0,
                    path(record.ty, strong),
                    path(record.ty, idle),
                    from_bucket(key_ptr),
                    from_bucket(entries_ptr),
                    type_name(*entry),
                    path(*entry, want)
                );
            }
            Some(HttpPoolBinding::Checkout {
                rule,
                key_ptr,
                want,
                ..
            }) => {
                let _ = write!(
                    line,
                    " pool checkout rule {} key {} want {}",
                    rule.0,
                    path(record.ty, key_ptr),
                    path(record.ty, want)
                );
            }
            None => {}
        }
        if let Some(table) = &record.table {
            let _ = write!(
                line,
                " table rule {} mask {} ctrl {} items {} bucket {}",
                table.rule.0,
                path(record.ty, &table.bucket_mask),
                path(record.ty, &table.ctrl),
                path(record.ty, &table.items),
                fq_name(bundle, table.bucket)
            );
        }
        if let Some(session) = &record.tls_session {
            let words = [
                ("state", &session.state),
                ("side", &session.side),
                ("negotiated", &session.negotiated_version),
                ("version", &session.version),
                ("send", &session.may_send_application_data),
                ("receive", &session.may_receive_application_data),
                ("sent-close", &session.has_sent_close_notify),
                ("received-close", &session.has_received_close_notify),
                ("eof", &session.has_seen_eof),
                ("fatal", &session.sent_fatal_alert),
                ("read-seq", &session.read_seq),
                ("write-seq", &session.write_seq),
                ("deframer-used", &session.deframer_used),
                ("deframer-len", &session.deframer_len),
            ]
            .map(|(what, word)| format!("{what} {}", path(record.ty, word)));
            let _ = write!(
                line,
                " tls-session rule {} {}",
                session.rule.0,
                words.join(" ")
            );
        }
        if let Some(stream) = &record.tls_stream {
            let _ = write!(
                line,
                " tls-stream rule {} session {} state {}",
                stream.rule.0,
                path(record.ty, &stream.session),
                path(record.ty, &stream.state)
            );
        }
        if let Some(peer) = &record.stream_peer {
            let _ = write!(
                line,
                " stream-peer rule {} name {}",
                peer.rule.0,
                path(record.ty, &peer.name)
            );
        }
        if let Some(refcount) = &record.refcount {
            let value = match refcount.value {
                MemberRef::Named(name) => s(name).to_owned(),
                MemberRef::Index(i) => format!("#{i}"),
            };
            let _ = write!(line, " refcount rule {} value {value}", refcount.rule.0);
        }
        if let Some(lock) = &record.lock {
            let _ = write!(
                line,
                " lock rule {} word {}+{} mask {:#x}",
                lock.rule.0, lock.word.offset, lock.word.size, lock.word.locked_mask
            );
        }
        if let Some(acquires) = &record.acquires_for {
            let _ = write!(
                line,
                " acquires-for rule {} {}",
                acquires.rule.0,
                s(acquires.primitive)
            );
        }
        if let Some(kind) = record.coroutine_kind {
            let _ = write!(line, " kind rule {}", kind.0);
        }
        if let Some(select) = &record.select {
            let branches: Vec<String> = select
                .branches
                .iter()
                .map(|b| path(select.futures.target, b))
                .collect();
            let arms: Vec<String> = select
                .arms
                .iter()
                .map(|arm| match arm {
                    Some(loc) => format!("{}:{}", s(loc.file), loc.line),
                    None => "-".to_owned(),
                })
                .collect();
            let _ = write!(
                line,
                " select rule {} mask {} futures {} branches [{}] arms [{}]",
                select.rule.0,
                path(record.ty, &select.mask),
                path(record.ty, &select.futures),
                branches.join(", "),
                arms.join(", ")
            );
        }
        for i in &record.issues {
            let _ = write!(line, " issue ({})", issue(i));
        }
        out.push_str(&line);
        out.push('\n');
    }
    for (i, entry) in bundle.tasks.entries.iter().enumerate() {
        let class = match &entry.scheduler_binding {
            Some(binding) => format!("{:?} rule {}", binding.class, binding.rule.0),
            None => "unknown".to_owned(),
        };
        let _ = writeln!(
            out,
            "task {i}: scheduler {} :: {class}",
            type_name(entry.scheduler)
        );
    }
    out
}

/// `--explain-future`: every emitted type whose name contains `want`,
/// with its semantic record rendered as [`describe_semantics`] does, or
/// the reasons a type without one has none — no positive evidence, not
/// a compiler-storage candidate, no reviewed layout route bound at it.
pub fn explain_future(bundle: &Bundle, want: &str) -> String {
    use std::fmt::Write;
    let s = |r| bundle.strings.get(r).unwrap_or("<bad strref>");
    let table = describe_semantics(bundle);
    let mut out = String::new();
    let mut matched = false;
    for &(name, id) in &bundle.types.name_index {
        let name = s(name);
        if !name.contains(want) {
            continue;
        }
        matched = true;
        let prefix = format!("{name} ::");
        match table.lines().find(|line| line.starts_with(&prefix)) {
            Some(line) => {
                let _ = writeln!(out, "{line}");
            }
            None => {
                let _ = writeln!(
                    out,
                    "{name} :: no semantic record — no task entry, poll symbol or \
                     delegation names it, it is not a compiler-storage candidate, and \
                     no reviewed resource, container or scheduler route bound at it"
                );
            }
        }
        let _ = id;
    }
    if !matched {
        let _ = writeln!(
            out,
            "no emitted type's name contains {want:?}; --include-type pulls in one \
             nothing else reaches"
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hansei_bundle::{Bundle, Encoding, StringInterner, TypeTable, VariantDef, VariantShape};

    struct Refs {
        value: hansei_bundle::StrRef,
        a: hansei_bundle::StrRef,
        ghost: hansei_bundle::StrRef,
    }

    /// A bundle whose enum keeps its payload away from offset zero, so a
    /// selector through a variant carries the payload offset visibly.
    fn bundle() -> (Bundle, Refs) {
        let mut strings = StringInterner::new();
        let u64n = strings.intern("u64");
        let payload_name = strings.intern("Payload");
        let value = strings.intern("value");
        let enum_name = strings.intern("E");
        let a = strings.intern("A");
        let ghost = strings.intern("ghost");
        let types = TypeTable {
            types: vec![
                TypeDef::Base {
                    name: u64n,
                    size: 8,
                    encoding: Encoding::Unsigned,
                },
                TypeDef::Struct {
                    name: payload_name,
                    size: 16,
                    members: vec![MemberDef {
                        name: value,
                        ty: BundleTypeId(0),
                        offset: 4,
                    }],
                },
                TypeDef::Enum {
                    name: enum_name,
                    size: 24,
                    shape: VariantShape {
                        discr: None,
                        variants: vec![VariantDef {
                            name: a,
                            discr_values: None,
                            payload: MemberDef {
                                name: a,
                                ty: BundleTypeId(1),
                                offset: 8,
                            },
                            decl: None,
                            await_site: None,
                        }],
                    },
                },
            ],
            ..Default::default()
        };
        let placeholder = BundleTypeId(0);
        let bundle = Bundle {
            meta: Default::default(),
            strings: strings.finish(),
            types,
            tasks: Default::default(),
            dyn_futures: Default::default(),
            statics: Default::default(),
            walks: Default::default(),
            infra: hansei_bundle::InfraTypes {
                header: placeholder,
                vtable: placeholder,
                trailer: placeholder,
                context: placeholder,
                scheduler_handle: placeholder,
                mt_handle: placeholder,
                ct_handle: placeholder,
                location: placeholder,
                raw_waker_vtable: placeholder,
            },
            provenance: Default::default(),
            impls: Default::default(),
            semantics: Default::default(),
        };
        (bundle, Refs { value, a, ghost })
    }

    fn describe_alias_at(bundle: &Bundle, root: u32, steps: Vec<Step>) -> String {
        let node = DisplayNode::Alias {
            at: hansei_bundle::Selector(steps),
            follow_pointers: true,
        };
        describe_node(bundle, BundleTypeId(root), &node)
    }

    fn describe_alias(bundle: &Bundle, steps: Vec<Step>) -> String {
        describe_alias_at(bundle, 2, steps)
    }

    #[test]
    fn test_selector_chains_accumulate_variant_payload_offsets() {
        let (bundle, refs) = bundle();
        let (a, value) = (refs.a, refs.value);

        // A named variant hop and the active-variant fan both add the
        // payload's own offset under the member's.
        let named = describe_alias(
            &bundle,
            vec![Step::Variant(a), Step::Member(MemberRef::Named(value))],
        );
        assert!(named.contains("{A}.value@+12"), "{named}");
        let fanned = describe_alias(
            &bundle,
            vec![Step::ActiveVariant, Step::Member(MemberRef::Named(value))],
        );
        assert!(fanned.contains("{A}.value@+12"), "{fanned}");
    }

    #[test]
    fn test_unresolvable_members_print_markers_not_panics() {
        let (bundle, refs) = bundle();

        let oob = describe_alias_at(&bundle, 1, vec![Step::Member(MemberRef::Index(9))]);
        assert!(oob.contains("<oob:9>"), "{oob}");
        let missing = describe_alias(
            &bundle,
            vec![
                Step::Variant(refs.a),
                Step::Member(MemberRef::Named(refs.ghost)),
            ],
        );
        assert!(missing.contains("<no unique member `ghost`>"), "{missing}");
    }
}
