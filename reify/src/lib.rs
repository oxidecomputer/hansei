//! Render values from a debug-info-described process image.

mod debug_type;
mod elements;
mod error;
pub mod heap;
mod parse;
pub mod path;
mod render;
mod target;
mod value;

#[cfg(test)]
mod testhelper;

pub use debug_type::TypeKind;
pub use elements::Elements;
pub use error::Error;
pub use heap::{Gate, Heap, Liveness};
pub use parse::ParseWithDbgInfo;
pub use render::{
    AddrAnnotator, DEFAULT_MAX_ARRAY_VALUES, DEFAULT_MAX_STRING_LEN, DisplayValue, ElideOverride,
};
pub use value::Value;

pub type Result<T> = std::result::Result<T, Error>;
