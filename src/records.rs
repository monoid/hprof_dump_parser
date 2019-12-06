use crate::decl::*;
use byteorder::{NativeEndian, NetworkEndian, ReadBytesExt};
use std::collections::HashMap;
use std::convert::{Into, TryFrom, TryInto};
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

pub(crate) fn read_class_description<R: Read>(
    substream: &mut R,
    id_reader: IdReader,
) -> Result<ClassDescription, Error> {
    let class_id: Id = id_reader.read_id(substream)?;
    let stack_trace_serial: SerialNumber = substream.read_u32::<NetworkEndian>()?;
    let super_class_object_id: Id = id_reader.read_id(substream)?;
    let class_loader_object_id: Id = id_reader.read_id(substream)?;
    let signers_object_id: Id = id_reader.read_id(substream)?;
    let protection_domain_object_id = id_reader.read_id(substream)?;
    let reserved1 = id_reader.read_id(substream)?;
    let reserved2 = id_reader.read_id(substream)?;

    let instance_size: u32 = substream.read_u32::<NetworkEndian>()?;

    let const_pool_size: u16 = substream.read_u16::<NetworkEndian>()?;
    let mut const_fields = Vec::with_capacity(const_pool_size as usize);
    for _idx in 0..const_pool_size {
        let const_pool_idx: u16 = substream.read_u16::<NetworkEndian>()?;
        let const_type: FieldType =
            FieldType::try_from(substream.read_u8()?).or(Err(Error::InvalidField("ty")))?;
        let const_value = read_type_value(substream, const_type, id_reader)?;

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
        let name_id: Id = id_reader.read_id(substream)?;
        let field_type: FieldType =
            FieldType::try_from(substream.read_u8()?).or(Err(Error::InvalidField("ty")))?;
        let field_value = read_type_value(substream, field_type, id_reader)?;

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
        let name_id: Id = id_reader.read_id(substream)?;
        let field_type: FieldType =
            FieldType::try_from(substream.read_u8()?).or(Err(Error::InvalidField("ty")))?;
        instance_fields.push(FieldInfo {
            name_id,
            field_type,
        });
    }

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

pub(crate) fn read_object<R: Read>(
    stream: &mut R,
    id_reader: IdReader,
    class_info: &HashMap<Id, ClassDescription>,
) -> Result<Vec<(Id, Id, FieldInfo, FieldValue)>, Error> {
    let object_id: Id = id_reader.read_id(stream)?;
    let stack_trace_serial: SerialNumber = stream.read_u32::<NetworkEndian>()?;
    let class_object_id: Id = id_reader.read_id(stream)?;
    let data_size: u64 = stream.read_u32::<NetworkEndian>()?.into();

    let mut substream = stream.take(data_size);
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
            values.push((object_id, current_class_obj_id, *field_info, field_value));
        }

        current_class_obj_id = class_desc.super_class_object_id;
    }

    Ok(values)
}

pub(crate) fn read_object_array<R: Read>(
    stream: &mut R,
    id_reader: IdReader,
) -> Result<(Id, Id, Vec<Id>), Error> {
    let object_id: Id = id_reader.read_id(stream)?;
    let stack_trace_serial: SerialNumber = stream.read_u32::<NetworkEndian>()?;
    let num_elements: usize = stream.read_u32::<NetworkEndian>()? as usize;
    let element_class_id: Id = id_reader.read_id(stream)?;

    let mut res = vec![Id::from(0 as u64); num_elements];

    for elt in res.iter_mut() {
        *elt = id_reader.read_id(stream)?;
    }

    Ok((object_id, element_class_id, res))
}

pub(crate) fn read_primitive_array<R: Read>(
    stream: &mut R,
    id_reader: IdReader,
) -> Result<(Id, ArrayValue), Error> {
    let object_id: Id = id_reader.read_id(stream)?;
    let stack_trace_serial: SerialNumber = stream.read_u32::<NetworkEndian>()?;
    let num_elemnts: usize = stream.read_u32::<NetworkEndian>()? as usize;
    let elem_type: FieldType =
        FieldType::try_from(stream.read_u8()?).or(Err(Error::InvalidField("ty")))?;

    Ok((
        object_id,
        match elem_type {
            FieldType::Object => return Err(Error::InvalidField("object type in primitive array")),
            FieldType::Bool => {
                let mut res: Vec<bool> = vec![false; num_elemnts];
                for elt in res.iter_mut() {
                    *elt = stream.read_u8()? != 0;
                }
                ArrayValue::Bool(res)
            }
            FieldType::Char => {
                let mut res: Vec<u16> = vec![0; num_elemnts];
                stream.read_u16_into::<NetworkEndian>(&mut res[..])?;
                ArrayValue::Char(res)
            }
            FieldType::Float => {
                let mut res: Vec<f32> = vec![0.0; num_elemnts];
                stream.read_f32_into::<NetworkEndian>(&mut res[..])?;
                ArrayValue::Float(res)
            }
            FieldType::Double => {
                let mut res: Vec<f64> = vec![0.0; num_elemnts];
                stream.read_f64_into::<NetworkEndian>(&mut res[..])?;
                ArrayValue::Double(res)
            }
            FieldType::Byte => {
                let mut res: Vec<i8> = vec![0; num_elemnts];
                stream.read_i8_into(&mut res[..])?;
                ArrayValue::Byte(res)
            }
            FieldType::Short => {
                let mut res: Vec<i16> = vec![0; num_elemnts];
                stream.read_i16_into::<NetworkEndian>(&mut res[..])?;
                ArrayValue::Short(res)
            }
            FieldType::Int => {
                let mut res: Vec<i32> = vec![0; num_elemnts];
                stream.read_i32_into::<NetworkEndian>(&mut res[..])?;
                ArrayValue::Int(res)
            }
            FieldType::Long => {
                let mut res: Vec<i64> = vec![0; num_elemnts];
                stream.read_i64_into::<NetworkEndian>(&mut res[..])?;
                ArrayValue::Long(res)
            }
        },
    ))
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
