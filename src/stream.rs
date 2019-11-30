use crate::decl::*;
use crate::records::*;
use crate::try_byteorder::ReadBytesTryExt;
use byteorder::{NetworkEndian, ReadBytesExt};
use std::collections::HashMap;
use std::io::{BufRead, Read, Take};
use std::str::from_utf8;

pub struct StreamHprofReader {
    banner: String,
    id_reader: IdReader,
    timestamp: Ts,
    id_byteorder: ByteOrder,
    load_primitive_arrays: bool,
    load_object_arrays: bool,
    // actually it is only iterator who needs the hash
    class_info: HashMap<Id, ClassDescription>,
    // ditto; Strings
    strings: HashMap<Id, Vec<u8>>,
}

enum IteratorState<'stream, R: Read> {
    Eof,
    InData(Ts, Take<&'stream mut R>),
    InNormal(&'stream mut R),
}

pub struct StreamHprofIterator<'stream, 'hprof, R: Read> {
    state: IteratorState<'stream, R>,
    // TODO: just copy params from StreamHprofReader
    hprof: &'hprof mut StreamHprofReader,
}

impl StreamHprofReader {
    pub fn new() -> Self {
        Self {
            banner: String::new(),
            id_reader: IdReader::new(),
            timestamp: 0,
            id_byteorder: ByteOrder::Native,
            load_primitive_arrays: true,
            load_object_arrays: true,
            class_info: HashMap::new(),
            strings: HashMap::new(),
        }
    }

    pub fn with_id_byteorder(mut self, id_byteorder: ByteOrder) -> Self {
        self.id_reader.order = id_byteorder;
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
        &'hprof mut self,
        stream: &'stream mut R,
    ) -> Result<StreamHprofIterator<'stream, 'hprof, R>, Error> {
        // Read header first
        // Using split looks unreliable.  Reading byte-by-byte looks more reliable and doesn't require
        // a BufRead (though why not?).
        self.banner = from_utf8(&stream.split(0x00).next().unwrap()?[..])
            .or(Err(Error::InvalidHeader(
                "Failed to parse file banner in header",
            )))?
            .to_string(); // TODO get rid of unwrap
        self.id_reader.id_size = stream.read_u32::<NetworkEndian>()?;

        // It can be read as u64 as well, but we follow the spec.
        let hi = stream.read_u32::<NetworkEndian>()? as u64;
        let lo = stream.read_u32::<NetworkEndian>()? as u64;
        self.timestamp = (hi << 32) | lo;

        Ok(StreamHprofIterator {
            state: IteratorState::InNormal(stream),
            hprof: self,
        })
    }
}

impl<'stream, 'hprof, R: Read> StreamHprofIterator<'stream, 'hprof, R> {
    fn read_record(&mut self) -> Option<Result<Record, Error>> {
	match &self.state {
	    IteratorState::InNormal(ref stream) => {
		let tag = match stream.try_read_u8() {
		    Some(Ok(value)) => value,
		    other => {
			self.state = IteratorState::Eof;
			// We have to convert Result<u16, io::Error> to Result<DumpRecord, Error>
			return other
			    .map(|r| r.map(|_| unreachable!()).or_else(|e| Err(e.into())));
		    }
		};

		let timestamp_delta: u64 = match stream.read_u32::<NetworkEndian>() {
		    Ok(v) => v.into(),
		    Err(err) => return Some(Err(err.into())),
		};
		let payload_size: u32 = match stream.read_u32::<NetworkEndian>() {
		    Ok(v) => v.into(),
		    Err(err) => return Some(Err(err.into())),
		};

		let id_reader = self.hprof.id_reader;
		let timestamp = self.hprof.timestamp + timestamp_delta;

		match tag {
		    TAG_STRING => {
			Some(
			    read_01_string(*stream, id_reader, payload_size).and_then(
				|(id, data)| {
				    self.hprof.strings.insert(id, data.clone());
				    Ok(Record::String(timestamp, id, data))
				}
			    )
			)
		    }
		    TAG_LOAD_CLASS => {
			Some(
			    read_02_load_class(*stream, id_reader).and_then(
				|class_record| Ok(Record::LoadClass(timestamp, class_record))
			    )
			)
		    }
		    TAG_UNLOAD_CLASS => {
			Some(
			    read_03_unload_class(*stream).and_then(
				|serial| Ok(Record::UnloadClass(timestamp, serial))
			    )
			)
		    }
		    TAG_STACK_FRAME => {
			Some(
			    read_04_frame(*stream, id_reader).and_then(
				|frame| Ok(Record::StackFrame(timestamp, frame))
			    )
			)
		    }
		    TAG_STACK_TRACE => {
			Some(
			    read_05_trace(*stream, id_reader).and_then(
				|trace| Ok(Record::StackTrace(timestamp, trace))
			    )
			)
		    }
		    TAG_ALLOC_SITES => {
			Some(
			    read_06_alloc_sites(*stream).and_then(
				|alloc| Ok(Record::AllocSites(timestamp, alloc))
			    )
			)
		    }
		    TAG_HEAP_SUMMARY => {
			Some(
			    read_07_heap_summary(*stream).and_then(
				|heap_summary| Ok(Record::HeapSummary(timestamp, heap_summary))
			    )
			)
		    }
		    TAG_START_THREAD => {
			Some(
			    read_0a_start_thread(*stream, id_reader).and_then(
				|start_thread| Ok(Record::StartThread(timestamp, start_thread))
			    )
			)
		    }
		    TAG_END_THREAD => {
			Some(
			    read_0b_end_thread(*stream).and_then(
				|end_thread| Ok(Record::EndThread(timestamp, end_thread))
			    )
			)
		    }
		    TAG_HEAP_DUMP | TAG_HEAP_DUMP_SEGMENT => {
			// TODO: some kind of swap
			self.state = IteratorState::InData(timestamp, stream.take(payload_size.into()));
			
			return self.read_data_record()
			    
		    }
		    _ => Some(Err(Error::UnknownPacket(tag, payload_size))),
		}
	    }
	    _ => unreachable!(),
	}
    }

    fn read_data_record(&mut self) -> Option<Result<Record, Error>> {
	match self.state {
	    IteratorState::InData(ts, ref mut substream) => {
		let try_tag =  substream.try_read_u8();
		if let None = try_tag {
		    // End of data segment
		    self.state = IteratorState::InNormal(substream.into_inner());
		    return self.read_record()
		}

		// Use lambda to make ? work.
		let read_data = move || {
		    let tag = match try_tag {
			None => {
			    unreachable!{}
			}
			Some(Ok(value)) => value,
			Some(Err(err)) => {
			    self.state = IteratorState::Eof;
			    // We have to convert Result<u16, io::Error> to Result<DumpRecord, Error>
			    return Err(err.into());
			}
		    };
		    
		
		    let timestamp_delta: u64 = substream.read_u32::<NetworkEndian>()?.into();
		    let payload_size = substream.read_u32::<NetworkEndian>()?;
		
		    match tag {
			_ => {
			    return Err(Error::UnknownSubpacket(tag, payload_size));
			}
		    }
		};
		return Some(read_data())
	    }
	    _ => unreachable!()
	}
    }
}

impl<'hprof, 'stream, R: Read> Iterator for StreamHprofIterator<'hprof, 'stream, R> {
    type Item = Result<Record, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match &mut self.state {
                IteratorState::Eof => return None,
                IteratorState::InNormal(_) => {
                    return self.read_record().map(|ret| {
			match ret {
                            Ok(v) => Ok(v),
                            Err(e) => {
				self.state = IteratorState::Eof;
				Err(e)
                            }
			}
		    })
		}
                IteratorState::InData(_, _) => {
		    return self.read_data_record()
                }
            }
        }
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

        let mut hprof = StreamHprofReader::new();
        let mut it = hprof.read_hprof(&mut read).unwrap();

        for rec in it {
            // eprintln!("{:?}", rec);
        }

        assert!(hprof.timestamp != 0);
        assert!(hprof.id_reader.id_size == 8 || hprof.id_reader.id_size == 4); // Any value not equal to 8 is highly unlikely in 2019.
        assert_eq!(hprof.banner, "JAVA PROFILE 1.0.2"); // May suddenly fail if your version will change.

        let mut total_size: usize = 0;
        for (_, v) in hprof.strings {
            total_size += v.len();
        }
        eprintln!("Data size: {}", total_size);
    }
}
