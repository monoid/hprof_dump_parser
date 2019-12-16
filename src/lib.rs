pub mod decl;
pub mod reader;
pub mod records;
pub mod stream;
pub mod try_byteorder;

use decl::{ClassRecord, HprofHeader};
use std::collections::HashMap;

pub struct Class {
    pub record: ClassRecord,
    pub unloaded: bool,
}

pub struct HprofReader<Str> {
    pub header: HprofHeader<Str>,
    pub strings: HashMap<u64, Str>,
    pub classes: HashMap<u64, Class>,
}

impl<'a, Str: Clone + 'a> HprofReader<Str> {
    pub fn from_stream_reader(header: &HprofHeader<Str>) -> Self {
        Self {
            header: header.clone(),
            strings: HashMap::default(),
            classes: HashMap::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
