pub mod decl;
pub mod records;
pub mod stream;
pub mod try_byteorder;

use decl::{ClassRecord, HprofHeader};
use std::collections::HashMap;

pub struct Class {
    pub record: ClassRecord,
    pub unloaded: bool,
}

pub struct HprofReader {
    pub header: HprofHeader,
    pub strings: HashMap<u64, Vec<u8>>,
    pub classes: HashMap<u64, Class>,
}

impl HprofReader {
    pub fn from_stream_reader(header: &HprofHeader) -> Self {
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
