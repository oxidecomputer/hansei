//! Render values from a debug-info-described process image.

mod debug_type;
mod elements;
mod error;
mod parse;
mod render;
mod target;
mod value;

#[cfg(test)]
mod testhelper;

pub use debug_type::TypeKind;
pub use elements::Elements;
pub use error::Error;
pub use parse::ParseWithDbgInfo;
pub use render::{AddrAnnotator, DisplayValue, ElideOverride};
pub use value::Value;

pub type Result<T> = std::result::Result<T, Error>;
