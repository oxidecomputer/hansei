//! Render a [`DisplayNode`] as text: every selector resolved to its
//! field-name chain *and* byte offset, rooted the way resolution roots it.
//!
//! One renderer serves two readers. `exegesis dump` prints it so an operator
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
        } => {
            let capacity = match capacity {
                Some(capacity) => format!(", capacity={}", field(bundle, root, capacity)),
                None => String::new(),
            };
            format!(
                "Str {{ pointer={}, length={}{} }}",
                field(bundle, root, pointer),
                field(bundle, root, length),
                capacity,
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
            tail_offset,
        } => format!(
            "DynPointer {{ pointer={}, vtable={}, slots=[drop_in_place:{drop_in_place}, size:{size}, align:{align}], tail_offset={tail_offset} }}",
            field(bundle, root, pointer),
            field(bundle, root, vtable),
        ),
        DisplayNode::Map {
            length,
            key,
            value,
            entries,
        } => {
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
            } = entries.as_ref();
            let (_, _, root_ty) = walk(bundle, root, map_root);
            let some = some_payload(bundle, root_ty).unwrap_or(root_ty);
            let (_, _, node_ref) = walk(bundle, some, root_node);
            let (_, _, edges_ty) = walk(bundle, *internal, internal_edges);
            let edge_elem = array_elem(bundle, edges_ty).unwrap_or(*internal);
            format!(
                "Map {{ length={}, key={}, value={}, entries=BTree {{ root={}, root_node={}, \
                 height={}, node={}, leaf={}, leaf_len={}, leaf_keys={}, leaf_values={}, \
                 internal={}, internal_data={}, internal_edges={}, edge={} }} }}",
                field(bundle, root, length),
                fq_name(bundle, *key),
                fq_name(bundle, *value),
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
        DisplayNode::Elided => "Elided".to_owned(),
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
