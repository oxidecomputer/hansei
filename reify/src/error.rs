//! reify's error type.

use crate::debug_type::TypeKind;

/// TODO
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    backtrace: std::backtrace::Backtrace,
}

#[derive(thiserror::Error, Debug)]
enum ErrorKind {
    #[error("invalid discriminant value {discrim} for type {ty}")]
    InvalidDiscriminantValue { ty: String, discrim: i64 },
    #[error("unable to read member at range {start}..{end} from buf with len {len}")]
    InvalidMemberRange { start: u16, end: u16, len: u16 },
    #[error("enumerator {enum_name} not found for type {ty}")]
    NoEnumerator { ty: String, enum_name: String },
    #[error("member {member_name} not found for type {ty}")]
    NoMember { ty: String, member_name: String },
    #[error("attempted to dereference invalid address {addr:#x}")]
    InvalidAddr { addr: u64 },
    #[error("failed to parse type {0}")]
    ParseType(String),
    #[error("data length {actual} is does not match expected {expected} length")]
    UnexpectedLen { actual: u32, expected: u32 },
    #[error("expected a {expected} but found a {actual} when parsing {name}")]
    UnexpectedType {
        actual: TypeKind,
        expected: TypeKind,
        name: String,
    },
    #[error("expected enum variant {expected} was not active")]
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
    /// Creates a new error with backtrace capture.
    fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            source: None,
            backtrace: std::backtrace::Backtrace::capture(),
        }
    }

    /// Attaches a source error to this error.
    pub fn with_source<E>(mut self, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        self.source = Some(Box::new(source));
        self
    }

    /// Returns the backtrace captured when the error was created.
    pub fn backtrace(&self) -> &std::backtrace::Backtrace {
        &self.backtrace
    }

    pub fn invalid_discriminant_value(ty: String, discrim: i64) -> Self {
        Self::new(ErrorKind::InvalidDiscriminantValue { ty, discrim })
    }

    pub fn invalid_member_range(start: u16, end: u16, len: u16) -> Self {
        Self::new(ErrorKind::InvalidMemberRange { start, end, len })
    }

    pub fn no_enumerator(ty: String, enum_name: String) -> Self {
        Self::new(ErrorKind::NoEnumerator { ty, enum_name })
    }

    pub fn no_member(ty: String, member_name: String) -> Self {
        Self::new(ErrorKind::NoMember { ty, member_name })
    }

    pub fn invalid_addr(addr: u64) -> Self {
        Self::new(ErrorKind::InvalidAddr { addr })
    }

    pub fn parse_type(ty: impl Into<String>) -> Self {
        Self::new(ErrorKind::ParseType(ty.into()))
    }

    pub fn unexpected_len(actual: u32, expected: u32) -> Self {
        Self::new(ErrorKind::UnexpectedLen { actual, expected })
    }

    pub fn unexpected_type(actual: TypeKind, expected: TypeKind, name: String) -> Self {
        Self::new(ErrorKind::UnexpectedType {
            actual,
            expected,
            name,
        })
    }

    pub fn unexpected_variant(expected: String) -> Self {
        Self::new(ErrorKind::UnexpectedVariant { expected })
    }

    pub fn not_an_enum(ty: String) -> Self {
        Self::new(ErrorKind::NotAnEnum(ty))
    }

    pub fn not_a_sequence(ty: impl Into<String>) -> Self {
        Self::new(ErrorKind::NotASequence { ty: ty.into() })
    }

    pub fn invalid_sequence(ty: impl Into<String>, why: &'static str) -> Self {
        Self::new(ErrorKind::InvalidSequence { ty: ty.into(), why })
    }

    pub fn short_sequence(ty: impl Into<String>, claimed: u64, got: u64) -> Self {
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

// ---------------------------------------------------------------------------
// TypeInfo — owned typed buffer
// ---------------------------------------------------------------------------
