use std::convert::Into;
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

// TODO: u64 or template parameter.  One might use Vec<u8> or some
// more lightweight container (Id size never change after creation) to
// be fully bullet-proof.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct Id(usize);

impl Into<usize> for Id {
    fn into(self: Id) -> usize {
        self.0
    }
}

impl From<usize> for Id {
    fn from(id: usize) -> Id {
        Id(id)
    }
}

impl Into<u64> for Id {
    fn into(self: Id) -> u64 {
        self.0 as u64
    }
}

impl From<u64> for Id {
    fn from(id: u64) -> Id {
        Id(id as usize)
    }
}

impl From<u32> for Id {
    fn from(id: u32) -> Id {
        Id(id as usize)
    }
}

/// Timestamp
pub type Ts = u64;

/// Class serial number
pub type SerialNumber = u32;

#[derive(Debug)]
pub enum Record {
    String(Ts, Id, Vec<u8>),
    LoadClass(Ts, ClassRecord),
    UnloadClass(Ts, SerialNumber),
    StackFrame(Ts, StackFrameRecord),
    StackTrace(Ts, StackTraceRecord),
    AllocSites(Ts, AllocSitesRecord),
    HeapSummary(Ts, HeapSummaryRecord),
    StartThread(Ts, StartThreadRecord),
    EndThread(Ts, EndThreadRecord),
    Dump(Ts, DumpRecord),
}

#[derive(Clone, Debug)]
pub struct HprofHeader {
    pub format_name: Option<String>,
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

#[derive(Clone, Copy, Debug)]
pub enum FieldType {
    Bool,
    Byte,
    Char,
    Short,
    Int,
    Long,
    Float,
    Double,
    Object,
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
    Static,
    Object,
    Const,
}

#[derive(Clone, Copy, Debug)]
pub enum FieldAccess {
    Private,
    Protected,
    Default,
    Public,
}

#[derive(Clone, Debug)]
pub struct FieldInfo {
    name: String,
    type_: FieldType,
    lifetime: FieldLifeTime,
    access: FieldAccess,
}

/**
Class information: fields, etc.
*/
#[derive(Clone, Debug)]
pub struct ClassDescription {
    object_fields: Vec<FieldInfo>,
    class_fields: Vec<FieldInfo>,
    static_fields: Vec<FieldInfo>,
}

#[derive(Debug)]
pub enum DumpRecord {
    RootUnknown(Id),
    RootJniGlobal,
    RootJniLocal,
    RootJavaFrame,
    RootNativeStack,
    RootStickyClass,
    RootThreadBlock,
    RootMonitorUsed,
    RootThreadObject,
    ClassDump,
    InstanceDump,
    ObjectArrayDump,
    PrimitiveArrayDump,
}

// TODO it would be nice if errors contained file offsets.
#[derive(Debug)]
pub enum Error {
    /// Integer conversion
    IntegerConversionErrror,
    /// Header contains invalid data
    InvalidHeader(&'static str),
    /// Invalid UTF-8 string
    InvalidUtf8,
    /// Known packet contains invalid information
    InvalidPacket(u8, u32),
    /// Completely unknown packet type.
    UnknownPacket(u8, u32),
    /// Invalid HPROF_DATA subpacket
    InvalidSubpacket(u8, u32),
    /// Completely unknown HPROF_DATA subpacket type.
    UnknownSubpacket(u8, u32),
    /// Incomplete packet/subpacket
    PrematureEOF,
    /// Generic IO error
    UnderlyingIOError(io::Error),
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::UnderlyingIOError(error)
    }
}
