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
            return Err(Error::InvalidHeader("Id size not supported"));
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
    Ok(ClassRecord {
        serial: stream.read_u32::<NetworkEndian>()?,
        class_obj_id: id_reader.read_id(stream)?,
        stack_trace_serial: stream.read_u32::<NetworkEndian>()?,
        class_name_string_id: id_reader.read_id(stream)?,
    })
}

pub(crate) fn read_03_unload_class<T: Read>(stream: &mut T) -> Result<u32, Error> {
    Ok(stream.read_u32::<NetworkEndian>()?)
}

pub(crate) fn read_04_frame<T: Read>(
    stream: &mut T,
    id_reader: IdReader,
) -> Result<StackFrameRecord, Error> {
    Ok(StackFrameRecord {
        stack_frame_id: id_reader.read_id(stream)?,
        method_name_id: id_reader.read_id(stream)?,
        method_signature_id: id_reader.read_id(stream)?,
        source_file_name_id: id_reader.read_id(stream)?,
        class_serial: stream.read_u32::<NetworkEndian>()?,
        line_number: stream.read_i32::<NetworkEndian>()?,
    })
}

pub(crate) fn read_05_trace<T: Read>(
    stream: &mut T,
    id_reader: IdReader,
) -> Result<StackTraceRecord, Error> {
    let stack_trace_serial = stream.read_u32::<NetworkEndian>()?;
    let thread_serial = stream.read_u32::<NetworkEndian>()?;
    let num_frames = stream.read_u32::<NetworkEndian>()?;
    let mut stack_frame_ids = Vec::with_capacity(
        num_frames
            .try_into()
            .or(Err(Error::IntegerConversionErrror))?,
    );

    for _i in 0..num_frames {
        stack_frame_ids.push(id_reader.read_id(stream)?);
    }

    Ok(StackTraceRecord {
        stack_trace_serial,
        thread_serial,
        stack_frame_ids,
    })
}

pub(crate) fn read_06_alloc_sites<T: Read>(stream: &mut T) -> Result<AllocSitesRecord, Error> {
    let flags = stream.read_u16::<NetworkEndian>()?;
    let cutoff_ratio = stream.read_u32::<NetworkEndian>()?;
    let total_live_bytes = stream.read_u32::<NetworkEndian>()?;
    let total_live_instances = stream.read_u32::<NetworkEndian>()?;
    let total_bytes_allocated = stream.read_u64::<NetworkEndian>()?;
    let total_instances_allocated = stream.read_u64::<NetworkEndian>()?;
    let num_sites = stream.read_u32::<NetworkEndian>()?;
    let mut sites = Vec::with_capacity(
        num_sites
            .try_into()
            .or(Err(Error::IntegerConversionErrror))?,
    );

    for _i in 0..num_sites {
        sites.push(AllocSite {
            is_array: stream.read_u8()?,
            class_serial: stream.read_u32::<NetworkEndian>()?,
            stack_trace_serial: stream.read_u32::<NetworkEndian>()?,
            bytes_alive: stream.read_u32::<NetworkEndian>()?,
            instances_alive: stream.read_u32::<NetworkEndian>()?,
            bytes_allocated: stream.read_u32::<NetworkEndian>()?,
            instances_allocated: stream.read_u32::<NetworkEndian>()?,
        });
    }

    Ok(AllocSitesRecord {
        flags,
        cutoff_ratio,
        total_live_bytes,
        total_live_instances,
        total_bytes_allocated,
        total_instances_allocated,
        sites,
    })
}

pub(crate) fn read_07_heap_summary<T: Read>(stream: &mut T) -> Result<HeapSummaryRecord, Error> {
    Ok(HeapSummaryRecord {
        total_live_bytes: stream.read_u32::<NetworkEndian>()?,
        total_live_instances: stream.read_u32::<NetworkEndian>()?,
        total_bytes_allocated: stream.read_u64::<NetworkEndian>()?,
        total_instances_allocated: stream.read_u64::<NetworkEndian>()?,
    })
}

pub(crate) fn read_0a_start_thread<T: Read>(
    stream: &mut T,
    id_reader: IdReader,
) -> Result<StartThreadRecord, Error> {
    Ok(StartThreadRecord {
        thread_serial: stream.read_u32::<NetworkEndian>()?,
        thead_object_id: id_reader.read_id(stream)?,
        stack_trace_serial: stream.read_u32::<NetworkEndian>()?,
        thread_name_id: id_reader.read_id(stream)?,
        thread_group_name_id: id_reader.read_id(stream)?,
        thread_group_parent_name_id: id_reader.read_id(stream)?,
    })
}

pub(crate) fn read_0b_end_thread<T: Read>(stream: &mut T) -> Result<EndThreadRecord, Error> {
    Ok(EndThreadRecord {
        thread_serial: stream.read_u32::<NetworkEndian>()?,
    })
}
