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

/// Timestamp
pub type Ts = u64;

#[derive(Debug)]
pub enum Record {
    String(Ts, Id, Vec<u8>),
    LoadClass(Ts, ClassRecord),
    UnloadClass(Ts, Id),
    Stack(Ts, Id),
    AllocSite(Ts, Id),
    Thread(Ts, Id),
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
    pub serial: u32,
    pub class_obj_id: Id,
    pub stack_trace_serial: u32,
    pub class_name_string_id: Id,
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

#[derive(Clone, Copy, Debug)]
pub enum LifeTime {
    Static,
    Object,
}

#[derive(Clone, Copy, Debug)]
pub enum Access {
    Private,
    Default,
    Public,
}

#[derive(Clone, Debug)]
pub struct FieldInfo {
    name: String,
    type_: FieldType,
    lifetime: LifeTime,
    access: Access,
}

/**
Class information: fields, etc.
*/
#[derive(Clone, Debug)]
pub struct ClassDescription {
    object_fields: Vec<FieldInfo>,
    class_fields: Vec<FieldInfo>,
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

#[derive(Debug)]
pub enum Error {
    InvalidHeader,
    InvalidPacket(u8, usize),
    InvalidSubpacket,
    PrematureEOF,
    UnderlyingIOError(io::Error),
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::UnderlyingIOError(error)
    }
}
