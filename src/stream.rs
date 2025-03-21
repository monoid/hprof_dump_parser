#![forbid(unsafe_code)]

use crate::decl::*;
use crate::reader::*;
use crate::reader::{MainState, TakeState};
use crate::records::*;
use crate::try_byteorder::ReadBytesTryExt;
use byteorder::{NetworkEndian, ReadBytesExt};
use std::collections::HashMap;
use std::io::{self, BufRead};
use std::iter;
use std::marker::PhantomData;
use std::str::from_utf8;

pub struct StreamHprofReader {
    pub id_byteorder: ByteOrder,
    pub load_primitive_arrays: bool,
    pub load_object_arrays: bool,
}

enum IteratorState<R, T> {
    Eof,
    InData(Ts, T),
    InNormal(R),
}

impl<R, T> Default for IteratorState<R, T> {
    fn default() -> Self {
        Self::Eof
    }
}

impl<R, T> IteratorState<R, T> {
    fn take(&mut self) -> Self {
        std::mem::take(self)
    }
}

struct StreamHprofIterator<'stream, 'hprof, R, T> {
    pub banner: String,
    pub timestamp: Ts,
    state: IteratorState<R, T>,
    // TODO: just copy params from StreamHprofReader
    hprof: &'hprof StreamHprofReader,
    class_info: HashMap<Id, ClassDescription>,
    id_reader: IdReader,
    menace: PhantomData<&'stream ()>,
}

pub struct ReadHprofIterator<'hprof, R: io::BufRead> {
    iter: StreamHprofIterator<'hprof, 'hprof, MainStream<Stream<R>>, TakeStream<Stream<R>>>,
    pub timestamp: Ts,
    pub banner: String,
}

impl<'hprof, R: io::BufRead> ReadHprofIterator<'hprof, R> {
    fn new(
        iter: StreamHprofIterator<'hprof, 'hprof, MainStream<Stream<R>>, TakeStream<Stream<R>>>,
    ) -> Self {
        Self {
            timestamp: iter.timestamp,
            banner: iter.banner.clone(),
            iter,
        }
    }
}

pub struct MemoryHprofIterator<'data, 'hprof> {
    iter: StreamHprofIterator<'data, 'hprof, MainStream<Memory<'data>>, TakeStream<Memory<'data>>>,
    pub timestamp: Ts,
    pub banner: String,
}

impl<'data, 'hprof> MemoryHprofIterator<'data, 'hprof> {
    fn new(
        iter: StreamHprofIterator<
            'data,
            'hprof,
            MainStream<Memory<'data>>,
            TakeStream<Memory<'data>>,
        >,
    ) -> Self {
        Self {
            timestamp: iter.timestamp,
            banner: iter.banner.clone(),
            iter,
        }
    }
}

impl StreamHprofReader {
    #[inline]
    pub fn new() -> Self {
        Self {
            id_byteorder: ByteOrder::Native,
            load_primitive_arrays: true,
            load_object_arrays: true,
        }
    }

    #[inline]
    pub fn with_id_byteorder(mut self, id_byteorder: ByteOrder) -> Self {
        self.id_byteorder = id_byteorder;
        self
    }

    #[inline]
    pub fn with_load_primitive_arrays(mut self, flag: bool) -> Self {
        self.load_primitive_arrays = flag;
        self
    }

    #[inline]
    pub fn with_load_object_arrays(mut self, flag: bool) -> Self {
        self.load_object_arrays = flag;
        self
    }

    #[inline]
    pub fn read_hprof_from_stream<R: io::BufRead>(
        &self,
        stream: R,
    ) -> Result<ReadHprofIterator<'_, R>, Error> {
        self.read_hprof(MainStream(Stream(stream)))
            .map(ReadHprofIterator::new)
    }

    #[inline]
    pub fn read_hprof_from_memory<'data, 'hprof>(
        &'hprof self,
        data: &'data [u8],
    ) -> Result<MemoryHprofIterator<'data, 'hprof>, Error> {
        self.read_hprof(MainStream(Memory(data)))
            .map(MemoryHprofIterator::new)
    }

    fn read_hprof<'stream, 'hprof, R, T>(
        &'hprof self,
        mut stream: R,
    ) -> Result<StreamHprofIterator<'stream, 'hprof, R, T>, Error>
    where
        R: MainState<'stream, T>,
        T: TakeState<'stream, R>,
    {
        // Read header first
        // Using split looks unreliable.  Reading byte-by-byte looks more reliable and doesn't require
        // a BufRead (though why not?).

        let banner = from_utf8(&stream.reader().split(0x00).next().unwrap()?[..])
            .or(Err(Error::InvalidHeader(
                "Failed to parse banner in HPROF file header",
            )))?
            .to_string(); // TODO get rid of unwrap
        let mut id_reader = IdReader::new();
        id_reader.order = self.id_byteorder;
        id_reader.id_size = stream.reader().read_u32::<NetworkEndian>()?;
        if id_reader.id_size != 4 && id_reader.id_size != 8 {
            return Err(Error::IdSizeNotSupported(id_reader.id_size));
        }

        // It can be read as u64 as well, but we follow the spec. :)
        let hi: u64 = stream.reader().read_u32::<NetworkEndian>()?.into();
        let lo: u64 = stream.reader().read_u32::<NetworkEndian>()?.into();
        let timestamp = (hi << 32) | lo;

        Ok(StreamHprofIterator {
            banner,
            timestamp,
            state: IteratorState::InNormal(stream),
            hprof: self,
            class_info: HashMap::new(),
            id_reader,
            menace: PhantomData,
        })
    }
}

impl Default for StreamHprofReader {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

#[allow(type_alias_bounds)]
type Value<'stream, R, T>
where
    R: MainState<'stream, T>,
= (
    Ts,
    Record<<<R as MainState<'stream, T>>::Stream as ReadHprofString<'stream>>::String>,
);

impl<'stream, R, T> StreamHprofIterator<'stream, '_, R, T>
where
    R: MainState<'stream, T>,
    T: TakeState<'stream, R>,
{
    fn read_record(&mut self) -> Option<Result<Value<'stream, R, T>, Error>> {
        match self.state.take() {
            IteratorState::InNormal(mut main) => {
                let stream = main.reader();
                let tag = match stream.try_read_u8() {
                    Some(Ok(value)) => value,
                    other => {
                        // End of stream, be it an error or a real end.
                        self.state = IteratorState::Eof;
                        // We have to convert Result<u16, io::Error> to Result<DumpRecord, Error>
                        return other.map(|r| r.map(|_| unreachable!()).map_err(Into::into));
                    }
                };

                let timestamp_delta: u64 = match stream.read_u32::<NetworkEndian>() {
                    Ok(v) => v.into(),
                    Err(err) => {
                        return Some(Err(err.into()));
                    }
                };
                let payload_size = match stream.read_u32::<NetworkEndian>() {
                    Ok(v) => v,
                    Err(err) => {
                        return Some(Err(err.into()));
                    }
                };

                let id_reader = self.id_reader;
                let timestamp = self.timestamp + timestamp_delta;

                let retval = match tag {
                    TAG_STRING => Some(
                        read_01_string(stream, id_reader, payload_size)
                            .map(|(id, data)| (timestamp, Record::String(id, data))),
                    ),
                    TAG_LOAD_CLASS => Some(
                        read_02_load_class(stream, id_reader)
                            .map(|class_record| (timestamp, Record::LoadClass(class_record))),
                    ),
                    TAG_UNLOAD_CLASS => Some(
                        read_03_unload_class(stream)
                            .map(|serial| (timestamp, Record::UnloadClass(serial))),
                    ),
                    TAG_STACK_FRAME => Some(
                        read_04_frame(stream, id_reader)
                            .map(|frame| (timestamp, Record::StackFrame(frame))),
                    ),
                    TAG_STACK_TRACE => Some(
                        read_05_trace(stream, id_reader)
                            .map(|trace| (timestamp, Record::StackTrace(trace))),
                    ),
                    TAG_ALLOC_SITES => Some(
                        read_06_alloc_sites(stream)
                            .map(|alloc| (timestamp, Record::AllocSites(alloc))),
                    ),
                    TAG_HEAP_SUMMARY => Some(
                        read_07_heap_summary(stream)
                            .map(|heap_summary| (timestamp, Record::HeapSummary(heap_summary))),
                    ),
                    TAG_START_THREAD => Some(
                        read_0a_start_thread(stream, id_reader)
                            .map(|start_thread| (timestamp, Record::StartThread(start_thread))),
                    ),
                    TAG_END_THREAD => Some(
                        read_0b_end_thread(stream)
                            .map(|end_thread| (timestamp, Record::EndThread(end_thread))),
                    ),
                    TAG_HEAP_DUMP | TAG_HEAP_DUMP_SEGMENT => {
                        self.state = IteratorState::InData(
                            timestamp,
                            match main.take(payload_size) {
                                Ok(take) => take,
                                Err(err) => return Some(Err(err)),
                            },
                        );

                        return self.read_data_record();
                    }
                    TAG_HEAP_DUMP_END => {
                        // No data inside; just try to read next
                        // segment recursively
                        self.state = IteratorState::InNormal(main);

                        return self.read_record();
                    }
                    _ => Some(Err(Error::UnknownPacket(tag, payload_size))),
                };
                self.state = IteratorState::InNormal(main);
                retval
            }
            _ => unreachable!(),
        }
    }

    fn read_data_record(&mut self) -> Option<Result<Value<'stream, R, T>, Error>> {
        let id_reader = self.id_reader;
        let state = self.state.take();

        match state {
            IteratorState::InData(ts, mut subdata) => {
                let try_tag = subdata.reader().try_read_u8();
                match try_tag {
                    None => {
                        // End of data segment
                        let main = subdata.into_inner();
                        self.state = IteratorState::InNormal(main);
                        self.read_record()
                    }
                    Some(non_empty) => {
                        // Use lambda to make ? work.
                        let read_data = move || {
                            let mut substream = subdata.reader();
                            let tag = non_empty?;

                            let res = match tag {
                                TAG_GC_ROOT_UNKNOWN => {
                                    read_data_ff_root_unknown(&mut substream, id_reader)?
                                }
                                TAG_GC_ROOT_JNI_GLOBAL => {
                                    read_data_01_root_jni_global(&mut substream, id_reader)?
                                }
                                TAG_GC_ROOT_JNI_LOCAL => {
                                    read_data_02_root_jni_local(&mut substream, id_reader)?
                                }
                                TAG_GC_ROOT_JAVA_FRAME => {
                                    read_data_03_root_java_frame(&mut substream, id_reader)?
                                }
                                TAG_GC_ROOT_NATIVE_STACK => {
                                    read_data_04_root_native_stack(&mut substream, id_reader)?
                                }
                                TAG_GC_ROOT_STICKY_CLASS => {
                                    read_data_05_root_sticky_class(&mut substream, id_reader)?
                                }
                                TAG_GC_ROOT_THREAD_BLOCK => {
                                    read_data_06_root_thread_block(&mut substream, id_reader)?
                                }
                                TAG_GC_ROOT_MONITOR_USED => {
                                    read_data_07_root_monitor_used(&mut substream, id_reader)?
                                }
                                TAG_GC_ROOT_THREAD_OBJ => {
                                    read_data_08_root_thread_obj(&mut substream, id_reader)?
                                }
                                TAG_GC_CLASS_DUMP => {
                                    let class_info =
                                        read_data_20_class_dump(&mut substream, id_reader)?;
                                    self.class_info
                                        .insert(class_info.class_id, class_info.clone());
                                    DumpRecord::ClassDump(class_info)
                                }
                                TAG_GC_INSTANCE_DUMP => {
                                    let object_fields = read_data_21_instance_dump(
                                        &mut substream,
                                        id_reader,
                                        &self.class_info,
                                    )?;
                                    DumpRecord::InstanceDump(object_fields)
                                }
                                TAG_GC_OBJ_ARRAY_DUMP => {
                                    DumpRecord::ObjectArrayDump(read_data_22_object_array(
                                        &mut substream,
                                        id_reader,
                                        self.hprof.load_object_arrays,
                                    )?)
                                }
                                TAG_GC_PRIM_ARRAY_DUMP => {
                                    DumpRecord::PrimitiveArrayDump(read_data_23_primitive_array(
                                        &mut substream,
                                        id_reader,
                                        self.hprof.load_primitive_arrays,
                                    )?)
                                }
                                _ => {
                                    return Err(Error::UnknownSubpacket(tag));
                                }
                            };
                            self.state = IteratorState::InData(ts, subdata);
                            Ok((ts, Record::Dump(res)))
                        };
                        Some(read_data())
                    }
                }
            }
            _ => unreachable!(),
        }
    }
}

impl<'stream, R, T> Iterator for StreamHprofIterator<'stream, '_, R, T>
where
    R: MainState<'stream, T>,
    T: TakeState<'stream, R>,
{
    type Item = Result<Value<'stream, R, T>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.state {
            IteratorState::Eof => None,
            IteratorState::InNormal(_) => self.read_record(),
            IteratorState::InData(_, _) => self.read_data_record(),
        }
        .map(|ret| {
            ret.inspect_err(|_| {
                self.state = IteratorState::Eof;
            })
        })
    }
}

impl<'stream, R, T> iter::FusedIterator for StreamHprofIterator<'stream, '_, R, T>
where
    R: MainState<'stream, T> + Default,
    T: TakeState<'stream, R> + Default,
{
}

impl<'memory> Iterator for MemoryHprofIterator<'memory, '_> {
    type Item = Result<(Ts, Record<&'memory [u8]>), Error>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

impl iter::FusedIterator for MemoryHprofIterator<'_, '_> {}

impl<R: io::BufRead> Iterator for ReadHprofIterator<'_, R> {
    type Item = Result<(Ts, Record<Vec<u8>>), Error>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

impl<R: io::BufRead> iter::FusedIterator for ReadHprofIterator<'_, R> {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::BufReader;
    use std::iter::Iterator;

    // Prepare dump before running this test with a tool in ${PROJECT}/java dir
    #[ignore]
    #[test]
    fn test_with_4g_file() {
        let f = File::open("./java/dump.hprof")
            .expect("./java/hprof.dump not found. Please, create it manually.");
        let mut read = BufReader::new(f);

        let hprof = StreamHprofReader::new()
            .with_load_object_arrays(false)
            .with_load_primitive_arrays(false);
        let mut it = hprof.read_hprof_from_stream(&mut read).unwrap();

        for rec in it.by_ref() {
            eprintln!("{:?}", rec);
        }

        assert!(it.timestamp != 0);
        assert!(it.iter.id_reader.id_size == 8 || it.iter.id_reader.id_size == 4); // Any value not equal to 8 is highly unlikely in 2019.
        assert_eq!(it.banner, "JAVA PROFILE 1.0.2"); // May suddenly fail if your version will change.
    }

    #[ignore]
    #[test]
    fn test_with_4g_memory() {
        use std::io::Read;
        let mut f = File::open("./java/dump.hprof")
            .expect("./java/hprof.dump not found. Please, create it manually.");

        let mut data = vec![];
        f.read_to_end(&mut data)
            .expect("Failed to read test input data");

        let hprof = StreamHprofReader::new()
            .with_load_object_arrays(false)
            .with_load_primitive_arrays(false);
        let mut it = hprof.read_hprof_from_memory(&data).unwrap();

        for rec in it.by_ref() {
            eprintln!("{:?}", rec);
        }

        assert!(it.timestamp != 0);
        assert!(it.iter.id_reader.id_size == 8 || it.iter.id_reader.id_size == 4); // Any value not equal to 8 is highly unlikely in 2019.
        assert_eq!(it.banner, "JAVA PROFILE 1.0.2"); // May suddenly fail if your version will change.
    }
}
