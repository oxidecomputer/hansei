//! reify's error type.

use crate::debug_type::TypeKind;

/// Why a navigation or parse failed: a member or variant that is not there,
/// a buffer or address the bytes cannot back, a decode the value's bits do
/// not support. Rendered as prose by `Display` and chained through
/// [`std::error::Error::source`]; constructed only inside reify, so a caller
/// holds an opaque error and reports it.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

#[derive(thiserror::Error, Debug)]
enum ErrorKind {
    #[error("invalid discriminant value {discrim} for type {ty}")]
    InvalidDiscriminantValue { ty: String, discrim: i64 },
    #[error("member at {start}..{end} is outside the {len}-byte buffer")]
    InvalidMemberRange { start: u64, end: u64, len: u64 },
    #[error("type {ty} has no variant named {name}")]
    NoVariant { ty: String, name: String },
    #[error("type {ty} has no member named {name}")]
    NoMember { ty: String, name: String },
    #[error("cannot read target memory at {addr:#x}")]
    InvalidAddr { addr: u64 },
    #[error("failed to parse type {0}")]
    ParseType(String),
    #[error("value is {actual} bytes but the type needs {expected}")]
    UnexpectedLen { actual: u32, expected: u32 },
    #[error("expected a {expected} but found a {actual} when parsing {name}")]
    UnexpectedType {
        actual: TypeKind,
        expected: TypeKind,
        name: String,
    },
    #[error("variant {expected} is not active")]
    UnexpectedVariant { expected: String },
    #[error("{0} is not an enum type")]
    NotAnEnum(String),
    #[error("{ty} is not a sequence")]
    NotASequence { ty: String },
    #[error("{ty} has an unusable sequence header: {why}")]
    InvalidSequence { ty: String, why: &'static str },
    #[error("{ty} claims {claimed} elements but only {got} could be read")]
    ShortSequence { ty: String, claimed: u64, got: u64 },
}

impl Error {
    fn new(kind: ErrorKind) -> Self {
        Self { kind, source: None }
    }

    /// Attaches a source error to this error.
    pub(crate) fn with_source<E>(mut self, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        self.source = Some(Box::new(source));
        self
    }

    pub(crate) fn invalid_discriminant_value(ty: String, discrim: i64) -> Self {
        Self::new(ErrorKind::InvalidDiscriminantValue { ty, discrim })
    }

    pub(crate) fn invalid_member_range(start: u64, end: u64, len: u64) -> Self {
        Self::new(ErrorKind::InvalidMemberRange { start, end, len })
    }

    pub(crate) fn no_variant(ty: String, name: String) -> Self {
        Self::new(ErrorKind::NoVariant { ty, name })
    }

    pub(crate) fn no_member(ty: String, name: String) -> Self {
        Self::new(ErrorKind::NoMember { ty, name })
    }

    pub(crate) fn invalid_addr(addr: u64) -> Self {
        Self::new(ErrorKind::InvalidAddr { addr })
    }

    pub(crate) fn parse_type(ty: impl Into<String>) -> Self {
        Self::new(ErrorKind::ParseType(ty.into()))
    }

    pub(crate) fn unexpected_len(actual: u32, expected: u32) -> Self {
        Self::new(ErrorKind::UnexpectedLen { actual, expected })
    }

    pub(crate) fn unexpected_type(actual: TypeKind, expected: TypeKind, name: String) -> Self {
        Self::new(ErrorKind::UnexpectedType {
            actual,
            expected,
            name,
        })
    }

    pub(crate) fn unexpected_variant(expected: String) -> Self {
        Self::new(ErrorKind::UnexpectedVariant { expected })
    }

    pub(crate) fn not_an_enum(ty: String) -> Self {
        Self::new(ErrorKind::NotAnEnum(ty))
    }

    pub(crate) fn not_a_sequence(ty: impl Into<String>) -> Self {
        Self::new(ErrorKind::NotASequence { ty: ty.into() })
    }

    pub(crate) fn invalid_sequence(ty: impl Into<String>, why: &'static str) -> Self {
        Self::new(ErrorKind::InvalidSequence { ty: ty.into(), why })
    }

    pub(crate) fn short_sequence(ty: impl Into<String>, claimed: u64, got: u64) -> Self {
        Self::new(ErrorKind::ShortSequence {
            ty: ty.into(),
            claimed,
            got,
        })
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.kind.fmt(f)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| e.as_ref() as _)
    }
}
