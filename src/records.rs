#![forbid(unsafe_code)]

use crate::decl::*;
use crate::reader::*;
use byteorder::{NativeEndian, NetworkEndian, ReadBytesExt};
use std::collections::HashMap;
use std::convert::{Into, TryFrom, TryInto};
use std::io::{self, Read};

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

pub(crate) fn read_01_string<'a, R: Read + ReadHprofString<'a>>(
    stream: &mut R,
    id_reader: IdReader,
    mut payload_size: u32,
) -> Result<(Id, R::String), Error> {
    let id = id_reader.read_id(stream)?;
    payload_size -= id_reader.id_size;

    // Read string as byte vec or byte slice.  Contrary to
    // documentation, it is not always a valid utf-8 string.
    let data = stream.read_string(payload_size)?;

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

pub(crate) fn read_data_ff_root_unknown<T: Read>(
    stream: &mut T,
    id_reader: IdReader,
) -> Result<DumpRecord, Error> {
    Ok(DumpRecord::RootUnknown {
        obj_id: id_reader.read_id(stream)?,
    })
}

pub(crate) fn read_data_01_root_jni_global<T: Read>(
    stream: &mut T,
    id_reader: IdReader,
) -> Result<DumpRecord, Error> {
    Ok(DumpRecord::RootJniGlobal {
        obj_id: id_reader.read_id(stream)?,
        jni_global_ref: id_reader.read_id(stream)?,
    })
}

pub(crate) fn read_data_02_root_jni_local<T: Read>(
    stream: &mut T,
    id_reader: IdReader,
) -> Result<DumpRecord, Error> {
    Ok(DumpRecord::RootJniLocal {
        obj_id: id_reader.read_id(stream)?,
        thread_serial: stream.read_u32::<NetworkEndian>()?,
        frame_number: stream.read_u32::<NetworkEndian>()?,
    })
}

pub(crate) fn read_data_03_root_java_frame<T: Read>(
    stream: &mut T,
    id_reader: IdReader,
) -> Result<DumpRecord, Error> {
    Ok(DumpRecord::RootJavaFrame {
        obj_id: id_reader.read_id(stream)?,
        thread_serial: stream.read_u32::<NetworkEndian>()?,
        frame_number: stream.read_u32::<NetworkEndian>()?,
    })
}

pub(crate) fn read_data_04_root_native_stack<T: Read>(
    stream: &mut T,
    id_reader: IdReader,
) -> Result<DumpRecord, Error> {
    Ok(DumpRecord::RootNativeStack {
        obj_id: id_reader.read_id(stream)?,
        thread_serial: stream.read_u32::<NetworkEndian>()?,
    })
}

pub(crate) fn read_data_05_root_sticky_class<T: Read>(
    stream: &mut T,
    id_reader: IdReader,
) -> Result<DumpRecord, Error> {
    Ok(DumpRecord::RootStickyClass {
        obj_id: id_reader.read_id(stream)?,
    })
}

pub(crate) fn read_data_06_root_thread_block<T: Read>(
    stream: &mut T,
    id_reader: IdReader,
) -> Result<DumpRecord, Error> {
    Ok(DumpRecord::RootThreadBlock {
        obj_id: id_reader.read_id(stream)?,
        thread_serial: stream.read_u32::<NetworkEndian>()?,
    })
}

pub(crate) fn read_data_07_root_monitor_used<T: Read>(
    stream: &mut T,
    id_reader: IdReader,
) -> Result<DumpRecord, Error> {
    Ok(DumpRecord::RootMonitorUsed {
        obj_id: id_reader.read_id(stream)?,
    })
}

pub(crate) fn read_data_08_root_thread_obj<T: Read>(
    stream: &mut T,
    id_reader: IdReader,
) -> Result<DumpRecord, Error> {
    Ok(DumpRecord::RootThreadObject {
        obj_id: id_reader.read_id(stream)?,
        thread_serial: stream.read_u32::<NetworkEndian>()?,
        stack_trace_serial: stream.read_u32::<NetworkEndian>()?,
    })
}

pub(crate) fn read_data_20_class_dump<R: Read>(
    stream: &mut R,
    id_reader: IdReader,
) -> Result<ClassDescription, Error> {
    let class_id: Id = id_reader.read_id(stream)?;
    let stack_trace_serial: SerialNumber = stream.read_u32::<NetworkEndian>()?;
    let super_class_object_id: Id = id_reader.read_id(stream)?;
    let class_loader_object_id: Id = id_reader.read_id(stream)?;
    let signers_object_id: Id = id_reader.read_id(stream)?;
    let protection_domain_object_id = id_reader.read_id(stream)?;
    let reserved1 = id_reader.read_id(stream)?;
    let reserved2 = id_reader.read_id(stream)?;

    let instance_size: u32 = stream.read_u32::<NetworkEndian>()?;

    let mut substream = stream.take(instance_size as u64);

    let const_pool_size: u16 = substream.read_u16::<NetworkEndian>()?;
    let mut const_fields = Vec::with_capacity(const_pool_size as usize);
    for _idx in 0..const_pool_size {
        let const_pool_idx: u16 = substream.read_u16::<NetworkEndian>()?;
        let const_type: FieldType =
            FieldType::try_from(substream.read_u8()?).or(Err(Error::InvalidField("ty")))?;
        let const_value = read_type_value(&mut substream, const_type, id_reader)?;

        const_fields.push((
            ConstFieldInfo {
                const_pool_idx,
                const_type,
            },
            const_value,
        ));
    }

    let static_field_num: u16 = substream.read_u16::<NetworkEndian>()?;
    let mut static_fields = Vec::with_capacity(static_field_num as usize);
    for _idx in 0..static_field_num {
        let name_id: Id = id_reader.read_id(&mut substream)?;
        let field_type: FieldType =
            FieldType::try_from(substream.read_u8()?).or(Err(Error::InvalidField("ty")))?;
        let field_value = read_type_value(&mut substream, field_type, id_reader)?;

        static_fields.push((
            FieldInfo {
                name_id,
                field_type,
            },
            field_value,
        ));
    }

    let instance_fields_num: u16 = substream.read_u16::<NetworkEndian>()?;
    let mut instance_fields = Vec::with_capacity(instance_fields_num as usize);
    for _idx in 0..instance_fields_num {
        let name_id: Id = id_reader.read_id(&mut substream)?;
        let field_type: FieldType =
            FieldType::try_from(substream.read_u8()?).or(Err(Error::InvalidField("ty")))?;
        instance_fields.push(FieldInfo {
            name_id,
            field_type,
        });
    }

    io::copy(&mut substream, &mut io::sink())?;

    Ok(ClassDescription {
        class_id,
        stack_trace_serial,
        super_class_object_id,
        class_loader_object_id,
        signers_object_id,
        protection_domain_object_id,
        reserved1,
        reserved2,

        instance_size,

        const_fields,
        static_fields,
        instance_fields,
    })
}

pub(crate) fn read_data_21_instance_dump<R: Read>(
    stream: &mut R,
    id_reader: IdReader,
    class_info: &HashMap<Id, ClassDescription>,
) -> Result<InstanceDump, Error> {
    let object_id: Id = id_reader.read_id(stream)?;
    let stack_trace_serial: SerialNumber = stream.read_u32::<NetworkEndian>()?;
    let class_object_id: Id = id_reader.read_id(stream)?;
    let data_size = stream.read_u32::<NetworkEndian>()?;

    let mut substream = stream.take(data_size as u64);
    let mut values = Vec::new();

    // Read data class-by-class, going down into class hierarchy
    let mut current_class_obj_id = class_object_id;
    while Into::<u64>::into(current_class_obj_id) != 0 {
        let class_desc: &ClassDescription = class_info
            .get(&current_class_obj_id)
            .ok_or(Error::UnknownClass(current_class_obj_id))?;

        for field_info in class_desc.instance_fields.iter() {
            let field_value: FieldValue =
                read_type_value(&mut substream, field_info.field_type, id_reader)?;
            values.push((*field_info, field_value));
        }

        current_class_obj_id = class_desc.super_class_object_id;
    }

    io::copy(&mut substream, &mut io::sink())?;

    Ok(InstanceDump {
        object_id,
        stack_trace_serial,
        class_object_id,
        data_size,
        values,
    })
}

pub(crate) fn read_data_22_object_array<R: Read>(
    stream: &mut R,
    id_reader: IdReader,
    load_object_arrays: bool,
) -> Result<ObjectArrayDump, Error> {
    let object_id: Id = id_reader.read_id(stream)?;
    let stack_trace_serial: SerialNumber = stream.read_u32::<NetworkEndian>()?;
    let num_elements = stream.read_u32::<NetworkEndian>()?;
    let element_class_id: Id = id_reader.read_id(stream)?;

    // We cast u32 to usize here and at other places, however,
    // elsewhere we have a static_assert that u32 fits usize.
    let values = if load_object_arrays {
        let mut values = vec![Id::from(0u64); num_elements as usize];

        for elt in values.iter_mut() {
            *elt = id_reader.read_id(stream)?;
        }

        Some(values)
    } else {
        for _ in 0..num_elements {
            id_reader.read_id(stream)?;
        }
        None
    };

    Ok(ObjectArrayDump {
        object_id,
        stack_trace_serial,
        num_elements,
        element_class_id,
        values,
    })
}

pub(crate) fn read_data_23_primitive_array<R: Read>(
    stream: &mut R,
    id_reader: IdReader,
    load_primitive_arrays: bool,
) -> Result<PrimitiveArrayDump, Error> {
    let object_id: Id = id_reader.read_id(stream)?;
    let stack_trace_serial: SerialNumber = stream.read_u32::<NetworkEndian>()?;
    let num_elements = stream.read_u32::<NetworkEndian>()?;
    // TODO: use TryInto
    let num_elements_usize = num_elements as usize;
    let elem_type: FieldType =
        FieldType::try_from(stream.read_u8()?).or(Err(Error::InvalidField("type")))?;

    let values = if load_primitive_arrays {
        Some(match elem_type {
            FieldType::Object => return Err(Error::InvalidField("object type in primitive array")),
            FieldType::Bool => {
                let mut res: Vec<bool> = vec![false; num_elements_usize];
                for elt in res.iter_mut() {
                    *elt = stream.read_u8()? != 0;
                }
                ArrayValue::Bool(res)
            }
            FieldType::Char => {
                let mut res: Vec<u16> = vec![0; num_elements_usize];
                stream.read_u16_into::<NetworkEndian>(&mut res[..])?;
                ArrayValue::Char(res)
            }
            FieldType::Float => {
                let mut res: Vec<f32> = vec![0.0; num_elements_usize];
                stream.read_f32_into::<NetworkEndian>(&mut res[..])?;
                ArrayValue::Float(res)
            }
            FieldType::Double => {
                let mut res: Vec<f64> = vec![0.0; num_elements_usize];
                stream.read_f64_into::<NetworkEndian>(&mut res[..])?;
                ArrayValue::Double(res)
            }
            FieldType::Byte => {
                let mut res: Vec<i8> = vec![0; num_elements_usize];
                stream.read_i8_into(&mut res[..])?;
                ArrayValue::Byte(res)
            }
            FieldType::Short => {
                let mut res: Vec<i16> = vec![0; num_elements_usize];
                stream.read_i16_into::<NetworkEndian>(&mut res[..])?;
                ArrayValue::Short(res)
            }
            FieldType::Int => {
                let mut res: Vec<i32> = vec![0; num_elements_usize];
                stream.read_i32_into::<NetworkEndian>(&mut res[..])?;
                ArrayValue::Int(res)
            }
            FieldType::Long => {
                let mut res: Vec<i64> = vec![0; num_elements_usize];
                stream.read_i64_into::<NetworkEndian>(&mut res[..])?;
                ArrayValue::Long(res)
            }
        })
    } else {
        let field_byte_size = elem_type.byte_size()?;
        io::copy(
            &mut stream.take((num_elements as u64) * field_byte_size),
            &mut io::sink(),
        )?;
        None
    };
    Ok(PrimitiveArrayDump {
        object_id,
        stack_trace_serial,
        num_elements,
        elem_type,
        values,
    })
}

pub(crate) fn read_type_value<R: Read>(
    substream: &mut R,
    ty: FieldType,
    id_reader: IdReader,
) -> Result<FieldValue, Error> {
    Ok(match ty {
        FieldType::Object => FieldValue::Object(id_reader.read_id(substream)?),
        FieldType::Bool => FieldValue::Bool(substream.read_u8()? != 0),
        FieldType::Char => FieldValue::Char(substream.read_u16::<NetworkEndian>()?),
        FieldType::Float => FieldValue::Float(substream.read_f32::<NetworkEndian>()?),
        FieldType::Double => FieldValue::Double(substream.read_f64::<NetworkEndian>()?),
        FieldType::Byte => FieldValue::Byte(substream.read_i8()?),
        FieldType::Short => FieldValue::Short(substream.read_i16::<NetworkEndian>()?),
        FieldType::Int => FieldValue::Int(substream.read_i32::<NetworkEndian>()?),
        FieldType::Long => FieldValue::Long(substream.read_i64::<NetworkEndian>()?),
    })
}
