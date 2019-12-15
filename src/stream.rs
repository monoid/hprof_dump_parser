use crate::decl::*;
use crate::records::*;
use crate::try_byteorder::ReadBytesTryExt;
use byteorder::{NetworkEndian, ReadBytesExt};
use std::collections::HashMap;
use std::io::{BufRead, Read, Take};
use std::str::from_utf8;

pub struct StreamHprofReader {
    pub id_byteorder: ByteOrder,
    pub load_primitive_arrays: bool,
    pub load_object_arrays: bool,
}

enum IteratorState<'stream, R: Read> {
    Eof,
    InData(Ts, Take<&'stream mut R>),
    InNormal(&'stream mut R),
}

pub struct StreamHprofIterator<'stream, 'hprof, R: Read> {
    pub banner: String,
    pub timestamp: Ts,
    state: Option<IteratorState<'stream, R>>,
    // TODO: just copy params from StreamHprofReader
    hprof: &'hprof StreamHprofReader,
    class_info: HashMap<Id, ClassDescription>,
    id_reader: IdReader,
}

impl StreamHprofReader {
    pub fn new() -> Self {
        Self {
            id_byteorder: ByteOrder::Native,
            load_primitive_arrays: true,
            load_object_arrays: true,
        }
    }

    pub fn with_id_byteorder(mut self, id_byteorder: ByteOrder) -> Self {
        self.id_byteorder = id_byteorder;
        self
    }

    pub fn with_load_primitive_arrays(mut self, flag: bool) -> Self {
        self.load_primitive_arrays = flag;
        self
    }

    pub fn with_load_object_arrays(mut self, flag: bool) -> Self {
        self.load_object_arrays = flag;
        self
    }

    pub fn read_hprof<'stream, 'hprof, R: BufRead>(
        &'hprof self,
        stream: &'stream mut R,
    ) -> Result<StreamHprofIterator<'stream, 'hprof, R>, Error> {
        // Read header first
        // Using split looks unreliable.  Reading byte-by-byte looks more reliable and doesn't require
        // a BufRead (though why not?).
        let banner = from_utf8(&stream.split(0x00).next().unwrap()?[..])
            .or(Err(Error::InvalidHeader(
                "Failed to parse file banner in header",
            )))?
            .to_string(); // TODO get rid of unwrap
        let mut id_reader = IdReader::new();
        id_reader.order = self.id_byteorder;
        id_reader.id_size = stream.read_u32::<NetworkEndian>()?;
        if id_reader.id_size != 4 && id_reader.id_size != 8 {
            return Err(Error::IdSizeNotSupported(id_reader.id_size));
        }

        // It can be read as u64 as well, but we follow the spec.
        let hi: u64 = stream.read_u32::<NetworkEndian>()?.into();
        let lo: u64 = stream.read_u32::<NetworkEndian>()?.into();
        let timestamp = (hi << 32) | lo;

        Ok(StreamHprofIterator {
            banner,
            timestamp,
            state: Some(IteratorState::InNormal(stream)),
            hprof: self,
            class_info: HashMap::new(),
            id_reader,
        })
    }
}

impl Default for StreamHprofReader {
    fn default() -> Self {
        Self::new()
    }
}

impl<'stream, 'hprof, R: Read> StreamHprofIterator<'stream, 'hprof, R> {
    fn read_record(&mut self) -> Option<Result<(Ts, Record), Error>> {
        match self.state.take().unwrap() {
            IteratorState::InNormal(stream) => {
                let tag = match stream.try_read_u8() {
                    Some(Ok(value)) => value,
                    other => {
                        self.state = Some(IteratorState::Eof);
                        // We have to convert Result<u16, io::Error> to Result<DumpRecord, Error>
                        return other.map(|r| r.map(|_| unreachable!()).or_else(|e| Err(e.into())));
                    }
                };

                let timestamp_delta: u64 = match stream.read_u32::<NetworkEndian>() {
                    Ok(v) => v.into(),
                    Err(err) => {
                        return Some(Err(err.into()));
                    }
                };
                let payload_size: u32 = match stream.read_u32::<NetworkEndian>() {
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
                            .and_then(|(id, data)| Ok((timestamp, Record::String(id, data)))),
                    ),
                    TAG_LOAD_CLASS => Some(
                        read_02_load_class(stream, id_reader).and_then(|class_record| {
                            Ok((timestamp, Record::LoadClass(class_record)))
                        }),
                    ),
                    TAG_UNLOAD_CLASS => Some(
                        read_03_unload_class(stream)
                            .and_then(|serial| Ok((timestamp, Record::UnloadClass(serial)))),
                    ),
                    TAG_STACK_FRAME => Some(
                        read_04_frame(stream, id_reader)
                            .and_then(|frame| Ok((timestamp, Record::StackFrame(frame)))),
                    ),
                    TAG_STACK_TRACE => Some(
                        read_05_trace(stream, id_reader)
                            .and_then(|trace| Ok((timestamp, Record::StackTrace(trace)))),
                    ),
                    TAG_ALLOC_SITES => Some(
                        read_06_alloc_sites(stream)
                            .and_then(|alloc| Ok((timestamp, Record::AllocSites(alloc)))),
                    ),
                    TAG_HEAP_SUMMARY => {
                        Some(read_07_heap_summary(stream).and_then(|heap_summary| {
                            Ok((timestamp, Record::HeapSummary(heap_summary)))
                        }))
                    }
                    TAG_START_THREAD => Some(read_0a_start_thread(stream, id_reader).and_then(
                        |start_thread| Ok((timestamp, Record::StartThread(start_thread))),
                    )),
                    TAG_END_THREAD => Some(
                        read_0b_end_thread(stream)
                            .and_then(|end_thread| Ok((timestamp, Record::EndThread(end_thread)))),
                    ),
                    TAG_HEAP_DUMP | TAG_HEAP_DUMP_SEGMENT => {
                        self.state = Some(IteratorState::InData(
                            timestamp,
                            stream.take(payload_size.into()),
                        ));

                        return self.read_data_record();
                    }
                    TAG_HEAP_DUMP_END => {
                        // No data inside; just try to read next
                        // segment recursively
                        self.state = Some(IteratorState::InNormal(stream));

                        return self.read_record();
                    }
                    _ => Some(Err(Error::UnknownPacket(tag, payload_size))),
                };
                self.state = Some(IteratorState::InNormal(stream));
                retval
            }
            _ => unreachable!(),
        }
    }

    fn read_data_record(&mut self) -> Option<Result<(Ts, Record), Error>> {
        let id_reader = self.id_reader;
        let state = self.state.take().unwrap();

        match state {
            IteratorState::InData(ts, mut substream) => {
                let try_tag = substream.try_read_u8();
                if try_tag.is_none() {
                    // End of data segment
                    let stream = substream.into_inner();
                    self.state = Some(IteratorState::InNormal(stream));
                    self.read_record()
                } else {
                    // Use lambda to make ? work.
                    let read_data = move || {
                        let tag = match try_tag {
                            None => unreachable!(),
                            Some(Ok(value)) => value,
                            Some(Err(err)) => {
                                // We have to convert Result<u16, io::Error> to Result<DumpRecord, Error>
                                return Err(err.into());
                            }
                        };

                        let res = Ok((
                            ts,
                            Record::Dump(match tag {
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
                            }),
                        ));
                        self.state = Some(IteratorState::InData(ts, substream));
                        res
                    };
                    Some(read_data())
                }
            }
            _ => unreachable!(),
        }
    }
}

impl<'hprof, 'stream, R: Read> Iterator for StreamHprofIterator<'hprof, 'stream, R> {
    type Item = Result<(Ts, Record), Error>;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.state {
            Some(IteratorState::Eof) => None,
            Some(IteratorState::InNormal(_)) => self.read_record(),
            Some(IteratorState::InData(_, _)) => self.read_data_record(),
            None => panic!("Empty state in next. Shouldn't happen"),
        }
        .map(|ret| {
            ret.map_err(|e| {
                self.state = Some(IteratorState::Eof);
                e
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::BufReader;

    // Prepare dump before running this test with a tool in ${PROJECT}/java dir
    #[ignore]
    #[test]
    fn test_with_4g_file() {
        let f = File::open("./java/dump.hprof")
            .expect("./java/hprof.dump not found. Please, create it manually.");
        let mut read = BufReader::new(f);

        let mut hprof = StreamHprofReader::new()
            .with_load_object_arrays(false)
            .with_load_primitive_arrays(false);
        let it = hprof.read_hprof(&mut read).unwrap();

        for rec in it {
            eprintln!("{:?}", rec);
        }

        assert!(hprof.timestamp != 0);
        assert!(hprof.id_reader.id_size == 8 || hprof.id_reader.id_size == 4); // Any value not equal to 8 is highly unlikely in 2019.
        assert_eq!(hprof.banner, "JAVA PROFILE 1.0.2"); // May suddenly fail if your version will change.
    }
}
