//! Render values from a debug-info-described process image.

pub mod debug_type;
mod elements;
mod error;
mod parse;
mod render;
mod target;
mod value;

#[cfg(test)]
mod testhelper;

pub use debug_type::TypeKind;
pub use elements::{Elements, MAX_SEQUENCE_BYTES};
pub use error::Error;
pub use parse::{ParseCtx, ParseWithDbgInfo};
pub use render::{AddrAnnotator, DisplayTargetValue, DisplayValue, ElideOverride};
pub use target::ReadFromProc;
pub use value::{TypeInfo, TypeInfoRef};

pub type Result<T> = std::result::Result<T, Error>;
