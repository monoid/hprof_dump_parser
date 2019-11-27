use crate::decl::*;
use byteorder::{NativeEndian, NetworkEndian, ReadBytesExt};
use std::convert::TryInto;
use std::io::Read;

#[derive(Clone, Copy, Debug)]
pub enum ByteOrder {
    Native,
    Network,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct IdReader {
    pub(crate) id_size: u32,
    pub(crate) order: ByteOrder,
}

impl IdReader {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn read_id<T: Read>(self, stream: &mut T) -> Result<Id, Error> {
        (if self.id_size == 4 {
            match self.order {
                ByteOrder::Native => stream.read_u32::<NativeEndian>(),
                ByteOrder::Network => stream.read_u32::<NetworkEndian>(),
            }
            .map(|v| v.into())
        } else if self.id_size == 8 {
            match self.order {
                ByteOrder::Native => stream.read_u64::<NativeEndian>(),
                ByteOrder::Network => stream.read_u64::<NetworkEndian>(),
            }
            .map(|v| v.into())
        } else {
            return Err(Error::InvalidHeader);
        })
        .map_err(|e| e.into())
    }
}

impl Default for IdReader {
    fn default() -> Self {
        Self {
            id_size: 0,
            order: ByteOrder::Network,
        }
    }
}

pub(crate) fn read_01_string<T: Read>(
    stream: &mut T,
    id_reader: IdReader,
    mut payload_size: u32,
) -> Result<(Id, Vec<u8>), Error> {
    let id = id_reader.read_id(stream)?;
    payload_size -= id_reader.id_size as u32;

    // Read string as byte vec.  Contrary to documentation, it
    // is not always a valid utf-8 string.
    let mut data = vec![0; payload_size.try_into().unwrap()];
    stream.read_exact(&mut data[..])?;

    Ok((id, data))
}

pub(crate) fn read_02_load_class<T: Read>(
    stream: &mut T,
    id_reader: IdReader,
) -> Result<ClassRecord, Error> {
    let serial: u32 = stream.read_u32::<NetworkEndian>()?;
    let class_obj_id = id_reader.read_id(stream)?;
    let stack_trace_serial: u32 = stream.read_u32::<NetworkEndian>()?;
    let class_name_string_id = id_reader.read_id(stream)?;

    Ok(ClassRecord {
        serial,
        class_obj_id,
        stack_trace_serial,
        class_name_string_id,
    })
}
