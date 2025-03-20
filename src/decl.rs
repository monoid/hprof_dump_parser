#![forbid(unsafe_code)]

use num_enum::TryFromPrimitive;
use std::io;

pub(crate) const TAG_STRING: u8 = 0x01;
pub(crate) const TAG_LOAD_CLASS: u8 = 0x02;
pub(crate) const TAG_UNLOAD_CLASS: u8 = 0x03;
pub(crate) const TAG_STACK_FRAME: u8 = 0x04;
pub(crate) const TAG_STACK_TRACE: u8 = 0x05;
pub(crate) const TAG_ALLOC_SITES: u8 = 0x06;
pub(crate) const TAG_HEAP_SUMMARY: u8 = 0x07;
pub(crate) const TAG_START_THREAD: u8 = 0x0A;
pub(crate) const TAG_END_THREAD: u8 = 0x0B;
pub(crate) const TAG_HEAP_DUMP: u8 = 0x0C;
pub(crate) const TAG_HEAP_DUMP_SEGMENT: u8 = 0x1C;
pub(crate) const TAG_HEAP_DUMP_END: u8 = 0x2C;

pub(crate) const TAG_GC_ROOT_UNKNOWN: u8 = 0xFF;
pub(crate) const TAG_GC_ROOT_JNI_GLOBAL: u8 = 0x01;
pub(crate) const TAG_GC_ROOT_JNI_LOCAL: u8 = 0x02;
pub(crate) const TAG_GC_ROOT_JAVA_FRAME: u8 = 0x03;
pub(crate) const TAG_GC_ROOT_NATIVE_STACK: u8 = 0x04;
pub(crate) const TAG_GC_ROOT_STICKY_CLASS: u8 = 0x05;
pub(crate) const TAG_GC_ROOT_THREAD_BLOCK: u8 = 0x06;
pub(crate) const TAG_GC_ROOT_MONITOR_USED: u8 = 0x07;
pub(crate) const TAG_GC_ROOT_THREAD_OBJ: u8 = 0x08;
pub(crate) const TAG_GC_CLASS_DUMP: u8 = 0x20;
pub(crate) const TAG_GC_INSTANCE_DUMP: u8 = 0x21;
pub(crate) const TAG_GC_OBJ_ARRAY_DUMP: u8 = 0x22;
pub(crate) const TAG_GC_PRIM_ARRAY_DUMP: u8 = 0x23;

// TODO: u64 or template parameter.  One might use Vec<u8> or some
// more lightweight container (Id size never change after creation) to
// be future-proof.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct Id(usize);

impl From<Id> for usize {
    #[inline]
    fn from(val: Id) -> usize {
        val.0
    }
}

impl From<usize> for Id {
    #[inline]
    fn from(id: usize) -> Id {
        Id(id)
    }
}

impl From<Id> for u64 {
    #[inline]
    fn from(val: Id) -> u64 {
        val.0 as u64
    }
}

impl From<u64> for Id {
    #[inline]
    fn from(id: u64) -> Id {
        Id(id as usize)
    }
}

impl From<u32> for Id {
    #[inline]
    fn from(id: u32) -> Id {
        Id(id as usize)
    }
}

/// Timestamp
pub type Ts = u64;

/// Class serial number
pub type SerialNumber = u32;

#[derive(Debug)]
pub enum Record<Str> {
    String(Id, Str),
    LoadClass(ClassRecord),
    UnloadClass(SerialNumber),
    StackFrame(StackFrameRecord),
    StackTrace(StackTraceRecord),
    AllocSites(AllocSitesRecord),
    HeapSummary(HeapSummaryRecord),
    StartThread(StartThreadRecord),
    EndThread(EndThreadRecord),
    Dump(DumpRecord),
}

#[derive(Clone, Debug)]
pub struct HprofHeader<Str> {
    pub format_name: Option<Str>,
    pub id_size: u32,
    pub timestamp: u64,
}

#[derive(Clone, Debug)]
pub struct ClassRecord {
    pub serial: SerialNumber,
    pub class_obj_id: Id,
    pub stack_trace_serial: u32,
    pub class_name_string_id: Id,
}

#[derive(Clone, Debug)]
pub struct StackFrameRecord {
    pub stack_frame_id: Id,
    pub method_name_id: Id,
    pub method_signature_id: Id,
    pub source_file_name_id: Id,
    pub class_serial: SerialNumber,
    pub line_number: i32,
}

#[derive(Clone, Debug)]
pub struct StackTraceRecord {
    pub stack_trace_serial: SerialNumber,
    pub thread_serial: SerialNumber,
    pub stack_frame_ids: Vec<Id>,
}

#[derive(Clone, Debug)]
pub struct AllocSite {
    pub is_array: u8,
    pub class_serial: SerialNumber,
    pub stack_trace_serial: SerialNumber,
    pub bytes_alive: u32,
    pub instances_alive: u32,
    pub bytes_allocated: u32,
    pub instances_allocated: u32,
}

#[derive(Clone, Debug)]
pub struct AllocSitesRecord {
    pub flags: u16,
    pub cutoff_ratio: u32,
    pub total_live_bytes: u32,
    pub total_live_instances: u32,
    pub total_bytes_allocated: u64,
    pub total_instances_allocated: u64,
    pub sites: Vec<AllocSite>,
}

#[derive(Clone, Debug)]
pub struct HeapSummaryRecord {
    pub total_live_bytes: u32,
    pub total_live_instances: u32,
    pub total_bytes_allocated: u64,
    pub total_instances_allocated: u64,
}

#[derive(Clone, Debug)]
pub struct StartThreadRecord {
    pub thread_serial: SerialNumber,
    pub thead_object_id: Id,
    pub stack_trace_serial: SerialNumber,
    pub thread_name_id: Id,
    pub thread_group_name_id: Id,
    pub thread_group_parent_name_id: Id,
}

#[derive(Clone, Debug)]
pub struct EndThreadRecord {
    pub thread_serial: SerialNumber,
}

#[derive(Clone, Copy, Debug, TryFromPrimitive)]
#[repr(u8)]
pub enum FieldType {
    Object = 2,
    Bool = 4,
    Char = 5,
    Float = 6,
    Double = 7,
    Byte = 8,
    Short = 9,
    Int = 10,
    Long = 11,
}

impl FieldType {
    /// Return storage byte size for each type.  Note that FieldType::Bool takes 1 byte.
    /// Return Error for FieldType::Object.
    pub fn byte_size(self) -> Result<u64, Error> {
        Ok(match self {
            FieldType::Object => return Err(Error::InvalidField("object type in primitive array")),
            FieldType::Byte | FieldType::Bool => 1,
            FieldType::Char | FieldType::Short => 2,
            FieldType::Float | FieldType::Int => 4,
            FieldType::Double | FieldType::Long => 8,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub enum FieldValue {
    Bool(bool),
    Byte(i8),
    Char(u16),
    Short(i16),
    Int(i32),
    Long(i64),
    Float(f32),
    Double(f64),
    Object(Id),
}

#[derive(Clone, Debug)]
pub enum ArrayValue {
    Bool(Vec<bool>),
    Byte(Vec<i8>),
    Char(Vec<u16>),
    Short(Vec<i16>),
    Int(Vec<i32>),
    Long(Vec<i64>),
    Float(Vec<f32>),
    Double(Vec<f64>),
    Object(Vec<Id>),
}

#[derive(Clone, Copy, Debug)]
pub enum FieldLifeTime {
    Const,
    Object,
    Static,
}

#[derive(Clone, Copy, Debug)]
pub struct ConstFieldInfo {
    pub const_pool_idx: u16,
    pub const_type: FieldType,
}

#[derive(Clone, Copy, Debug)]
pub struct FieldInfo {
    pub name_id: Id,
    pub field_type: FieldType,
}

/**
Class information: fields, etc.
*/
#[derive(Clone, Debug)]
pub struct ClassDescription {
    pub class_id: Id,
    pub stack_trace_serial: SerialNumber,
    pub super_class_object_id: Id,
    pub class_loader_object_id: Id,
    pub signers_object_id: Id,
    pub protection_domain_object_id: Id,
    pub reserved1: Id,
    pub reserved2: Id,

    pub instance_size: u32,

    pub const_fields: Vec<(ConstFieldInfo, FieldValue)>,
    pub static_fields: Vec<(FieldInfo, FieldValue)>,
    pub instance_fields: Vec<FieldInfo>,
}

/**
Instance dump.
 */
#[derive(Clone, Debug)]
pub struct InstanceDump {
    pub object_id: Id,
    pub stack_trace_serial: SerialNumber,
    pub class_object_id: Id,
    pub data_size: u32,
    pub values: Vec<(FieldInfo, FieldValue)>,
}

/**
Array of Object (or any subclass).  It contains only Ids of objects,
i.e. their addresses.  You have to resolve them yourself.
 */
#[derive(Clone, Debug)]
pub struct ObjectArrayDump {
    pub object_id: Id,
    pub stack_trace_serial: SerialNumber,
    pub num_elements: u32,
    pub element_class_id: Id,
    pub values: Option<Vec<Id>>,
}

/**
Array of primitive values.
 */
#[derive(Clone, Debug)]
pub struct PrimitiveArrayDump {
    pub object_id: Id,
    pub stack_trace_serial: SerialNumber,
    pub num_elements: u32,
    pub elem_type: FieldType,
    pub values: Option<ArrayValue>,
}

#[derive(Clone, Debug)]
pub enum DumpRecord {
    RootUnknown {
        obj_id: Id,
    },
    RootJniGlobal {
        obj_id: Id,
        jni_global_ref: Id,
    },
    RootJniLocal {
        obj_id: Id,
        thread_serial: SerialNumber,
        frame_number: u32,
    },
    RootJavaFrame {
        obj_id: Id,
        thread_serial: SerialNumber,
        frame_number: u32,
    },
    RootNativeStack {
        obj_id: Id,
        thread_serial: SerialNumber,
    },
    RootStickyClass {
        obj_id: Id,
    },
    RootThreadBlock {
        obj_id: Id,
        thread_serial: SerialNumber,
    },
    RootMonitorUsed {
        obj_id: Id,
    },
    RootThreadObject {
        obj_id: Id,
        thread_serial: SerialNumber,
        stack_trace_serial: SerialNumber,
    },
    ClassDump(ClassDescription),
    InstanceDump(InstanceDump),
    ObjectArrayDump(ObjectArrayDump),
    PrimitiveArrayDump(PrimitiveArrayDump),
}

// TODO it would be nice if errors contained file offsets.
#[derive(Debug)]
pub enum Error {
    /// Id size not supported
    IdSizeNotSupported(u32),
    /// Integer conversion
    IntegerConversionErrror,
    /// Header contains invalid data
    InvalidHeader(&'static str),
    InvalidField(&'static str),
    /// Invalid UTF-8 string
    InvalidUtf8,
    /// Known packet contains invalid information
    InvalidPacket(u8, u32),
    /// Completely unknown packet type.
    UnknownPacket(u8, u32),
    /// Invalid HPROF_DATA subpacket
    InvalidSubpacket(u8, u32),
    /// Completely unknown HPROF_DATA subpacket type.
    UnknownSubpacket(u8),
    /// Unknown class (found an object of unknown class, thus unknown
    /// structure).  First element is a Class Id, second is an Object Id.
    UnknownClass(Id),
    /// Incomplete packet/subpacket
    PrematureEOF,
    /// Generic IO error
    UnderlyingIOError(io::Error),
}

impl From<io::Error> for Error {
    #[inline]
    fn from(error: io::Error) -> Self {
        Error::UnderlyingIOError(error)
    }
}
