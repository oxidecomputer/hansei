//! Render values from a debug-info-described process image.

pub mod debug_type;
mod error;
mod parse;
mod render;
mod target;
mod value;

#[cfg(test)]
mod testhelper;

pub use debug_type::TypeKind;
pub use error::Error;
pub use parse::{ParseCtx, ParseWithDbgInfo};
pub use render::{DisplayTargetValue, DisplayValue};
pub use target::ReadFromProc;
pub use value::{TypeInfo, TypeInfoRef};

pub type Result<T> = std::result::Result<T, Error>;
