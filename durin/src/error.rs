use std::fmt;

pub type Result<T> = std::result::Result<T, crate::error::Error>;

#[derive(Clone, Debug)]
pub struct Error {
    inner: Box<ErrorInner>,
}

impl Error {
    #[cold]
    #[inline(never)]
    pub(crate) fn custom<'a>(message: impl std::fmt::Display + 'a) -> Self {
        ErrorKind::Custom(CustomError::from_display(message)).into()
    }

    #[cold]
    #[inline(never)]
    pub(crate) fn index_out_of_range(index: u16, max: u16) -> Self {
        ErrorKind::IndexOutOfRange(IndexOutOfRangeError { index, max }).into()
    }

    #[cold]
    #[inline(never)]
    pub(crate) fn conversion(type_name: &'static str, value: u64) -> Self {
        ErrorKind::Conversion(ConversionError { type_name, value }).into()
    }

    #[cold]
    #[inline(never)]
    pub(crate) fn insertion(max: u16) -> Self {
        ErrorKind::Insertion(InsertionError { max }).into()
    }

    #[cold]
    #[inline(never)]
    pub(crate) fn invalid_utf8() -> Self {
        ErrorKind::InvalidUtf8.into()
    }

    #[cold]
    #[inline(never)]
    pub(crate) fn missing(type_name: &'static str, index: usize) -> Self {
        ErrorKind::MissingEntry(MissingEntryError { type_name, index }).into()
    }

    #[cold]
    #[inline(never)]
    pub(crate) fn offset_overflow(offset: usize, len: usize) -> Self {
        ErrorKind::OffsetOverflow(OffsetOverflowError { offset, len }).into()
    }

    #[cold]
    #[inline(never)]
    pub(crate) fn out_of_bounds(offset: usize, len: usize) -> Self {
        ErrorKind::OutOfBounds(OutOfBoundsError { offset, len }).into()
    }

    #[cold]
    #[inline(never)]
    pub(crate) fn read_object(field_name: &'static str) -> Self {
        ErrorKind::ReadField(ReadObjectError {
            obj_name: field_name,
        })
        .into()
    }

    #[cold]
    #[inline(never)]
    pub(crate) fn string_too_long(len: usize) -> Self {
        ErrorKind::StringTooLong(StringTooLongError { len }).into()
    }

    #[cold]
    #[inline(never)]
    pub(crate) fn too_large(size: usize, available: usize) -> Self {
        ErrorKind::TooLarge(TooLargeError { size, available }).into()
    }

    #[cold]
    #[inline(never)]
    pub(crate) fn write_field(field_name: &'static str) -> Self {
        ErrorKind::WriteField(WriteFieldError { field_name }).into()
    }

    #[cold]
    #[inline(never)]
    fn ctx(self, mut context: Error) -> Self {
        context.inner.cause = Some(self);
        context
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner.kind)?;

        let mut err = self;
        while let Some(cause) = &err.inner.cause {
            write!(f, ": {}", cause.inner.kind)?;
            err = cause;
        }
        Ok(())
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Debug)]
struct ErrorInner {
    kind: ErrorKind,
    cause: Option<Error>,
}

impl From<ErrorKind> for Error {
    #[inline(always)]
    fn from(kind: ErrorKind) -> Error {
        Error {
            inner: Box::new(ErrorInner { kind, cause: None }),
        }
    }
}

impl From<String> for Error {
    #[inline(always)]
    fn from(msg: String) -> Self {
        Error::custom(msg)
    }
}

#[derive(Clone, Debug)]
enum ErrorKind {
    Conversion(ConversionError),
    Custom(CustomError),
    IndexOutOfRange(IndexOutOfRangeError),
    Insertion(InsertionError),
    InvalidUtf8,
    MissingEntry(MissingEntryError),
    OffsetOverflow(OffsetOverflowError),
    OutOfBounds(OutOfBoundsError),
    ReadField(ReadObjectError),
    StringTooLong(StringTooLongError),
    TooLarge(TooLargeError),
    WriteField(WriteFieldError),
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conversion(ty) => ty.fmt(f),
            Self::Custom(msg) => msg.fmt(f),
            Self::IndexOutOfRange(index) => index.fmt(f),
            Self::Insertion(ins) => ins.fmt(f),
            Self::InvalidUtf8 => "invalid UTF-8 in string".fmt(f),
            Self::MissingEntry(miss) => miss.fmt(f),
            Self::OutOfBounds(out) => out.fmt(f),
            Self::OffsetOverflow(off) => off.fmt(f),
            Self::ReadField(field) => field.fmt(f),
            Self::StringTooLong(string) => string.fmt(f),
            Self::TooLarge(large) => large.fmt(f),
            Self::WriteField(field) => field.fmt(f),
        }
    }
}

#[derive(Clone, Debug)]
struct ConversionError {
    type_name: &'static str,
    value: u64,
}

impl fmt::Display for ConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} is not a valid value for {}",
            self.value, self.type_name
        )
    }
}

impl std::error::Error for ConversionError {}

#[derive(Clone, Debug)]
struct CustomError {
    msg: Box<str>,
}

impl CustomError {
    fn from_display<'a>(msg: impl std::fmt::Display + 'a) -> CustomError {
        let msg = msg.to_string().into_boxed_str();
        CustomError { msg }
    }
}

impl fmt::Display for CustomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.msg, f)
    }
}

impl std::error::Error for CustomError {}

#[derive(Clone, Debug)]
struct InsertionError {
    max: u16,
}

impl fmt::Display for InsertionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "failed to insert item, cache has reached its max capacity of {}",
            self.max,
        )
    }
}

impl std::error::Error for InsertionError {}

#[derive(Clone, Debug)]
struct IndexOutOfRangeError {
    index: u16,
    max: u16,
}

impl fmt::Display for IndexOutOfRangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "index {} is greater than maximum of {}",
            self.index, self.max
        )
    }
}

impl std::error::Error for IndexOutOfRangeError {}

#[derive(Clone, Debug)]
struct MissingEntryError {
    type_name: &'static str,
    index: usize,
}

impl fmt::Display for MissingEntryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} at index {} not present in table",
            self.type_name, self.index
        )
    }
}

impl std::error::Error for MissingEntryError {}

#[derive(Clone, Debug)]
struct OffsetOverflowError {
    offset: usize,
    len: usize,
}

impl fmt::Display for OffsetOverflowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "integer overflow when incrementing offset {} by {}",
            self.offset, self.len
        )
    }
}

impl std::error::Error for OffsetOverflowError {}

#[derive(Clone, Debug)]
struct OutOfBoundsError {
    offset: usize,
    len: usize,
}

impl fmt::Display for OutOfBoundsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "offset {} out of bounds of source length {}",
            self.offset, self.len
        )
    }
}

impl std::error::Error for OutOfBoundsError {}

#[derive(Clone, Debug)]
struct ReadObjectError {
    obj_name: &'static str,
}

impl fmt::Display for ReadObjectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "failed to read {}", self.obj_name)
    }
}

impl std::error::Error for ReadObjectError {}

#[derive(Clone, Debug)]
struct StringTooLongError {
    len: usize,
}

impl fmt::Display for StringTooLongError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "string length {} greater than maximum of 32,000",
            self.len
        )
    }
}

impl std::error::Error for StringTooLongError {}

#[derive(Clone, Debug)]
struct TooLargeError {
    size: usize,
    available: usize,
}

impl fmt::Display for TooLargeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "object size {} is greater than available capacity {}",
            self.size, self.available
        )
    }
}

impl std::error::Error for TooLargeError {}

#[derive(Clone, Debug)]
struct WriteFieldError {
    field_name: &'static str,
}

impl fmt::Display for WriteFieldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "failed to write field '{}'", self.field_name)
    }
}

impl std::error::Error for WriteFieldError {}

pub(crate) trait ErrorContext {
    fn context(self, source: impl Into<Error>) -> Self;
    fn with_context(self, source: impl FnOnce() -> Error) -> Self;
    fn read_ctx(self, field: &'static str) -> Self;
    fn write_ctx(self, field: &'static str) -> Self;
}

impl<T> ErrorContext for Result<T> {
    fn context(self, source: impl Into<Error>) -> Result<T> {
        fn _context<U>(res: Result<U>, source: Error) -> Result<U> {
            match res {
                Ok(value) => Ok(value),
                Err(err) => Err(err.ctx(source)),
            }
        }
        _context(self, source.into())
    }

    #[inline]
    fn with_context(self, source: impl FnOnce() -> Error) -> Result<T> {
        match self {
            Ok(value) => Ok(value),
            Err(err) => Err(err.ctx(source())),
        }
    }

    #[inline]
    fn read_ctx(self, field: &'static str) -> Result<T> {
        self.with_context(|| Error::read_object(field))
    }

    #[inline]
    fn write_ctx(self, field: &'static str) -> Result<T> {
        self.with_context(|| Error::write_field(field))
    }
}
