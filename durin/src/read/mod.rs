use strings::UncheckedStringTable;

use flate2::read::ZlibDecoder;
use scroll::{Endian, Pread};

use std::io::Read;
use std::str;

mod error;
mod raw_types;
mod reader;
mod strings;
mod types;
mod view;

pub use error::Error;
pub use raw_types::{
    CtfLabel, RawCtfArray, RawCtfConst, RawCtfEnum, RawCtfEnumerator, RawCtfFloat, RawCtfForward,
    RawCtfFunction, RawCtfInteger, RawCtfMember, RawCtfPointer, RawCtfRestrict, RawCtfStruct,
    RawCtfType, RawCtfTypedef, RawCtfUnion, RawCtfUnknown, RawCtfVolatile,
};
pub use reader::CtfReader;
pub use strings::StringTable;
pub use types::{
    CtfArray, CtfConst, CtfEnum, CtfEnumerator, CtfEnumeratorIter, CtfFloat, CtfForward,
    CtfFunction, CtfFunctionArgIter, CtfInteger, CtfMember, CtfMemberIter, CtfPointer, CtfRestrict,
    CtfStruct, CtfType, CtfTypedef, CtfUnion, CtfUnknown, CtfVolatile,
};
pub use view::CtfView;

pub type Result<T> = std::result::Result<T, Error>;

const CTF_MAGIC_BYTES_BE: [u8; 2] = [0xcf, 0xf1];
const CTF_MAGIC_BYTES_LE: [u8; 2] = [0xf1, 0xcf];

// This assumes that the arch of the CTF data matches the target.
const POINTER_SIZE: u64 = size_of::<*const ()>() as u64;
