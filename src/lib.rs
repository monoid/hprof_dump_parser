#![forbid(unsafe_code)]

pub mod decl;
mod reader;
mod records;
pub mod stream;
mod try_byteorder;

#[macro_use]
extern crate static_assert_macro;

pub use stream::{MemoryHprofIterator, ReadHprofIterator, StreamHprofReader};
