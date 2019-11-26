use crate::decl::*;
use crate::try_byteorder::ReadBytesTryExt;
use byteorder::{NativeEndian, NetworkEndian, ReadBytesExt};
use std::collections::HashMap;
use std::convert::TryInto;
use std::io::{BufRead, Read, Take};
use std::str::from_utf8;

#[derive(Clone, Debug)]
pub enum ByteOrder {
    Native,
    Network,
    LittleEndian,
    BigEndian,
}

pub struct StreamHprofReader {
    banner: String,
    id_size: usize,
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
    InData(Ts, &'stream mut Take<R>),
    InNormal,
}

pub struct StreamHprofIterator<'stream, R: Read> {
    state: IteratorState<'stream, R>,
    // TODO: just copy params from StreamHprofReader
    hprof: &'stream mut StreamHprofReader,
    stream: &'stream mut R,
}

impl StreamHprofReader {
    pub fn new() -> Self {
        Self {
            banner: String::new(),
            id_size: 0,
            timestamp: 0,
            id_byteorder: ByteOrder::Native,
            load_primitive_arrays: true,
            load_object_arrays: true,
            class_info: HashMap::new(),
            strings: HashMap::new(),
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

    pub fn read_hprof<'a, R: BufRead>(
        &'a mut self,
        stream: &'a mut R,
    ) -> Result<StreamHprofIterator<'a, R>, Error> {
        // Read header first
        // Using split looks unreliable.  Reading byte-by-byte looks more reliable and doesn't require
        // a BufRead (though why not?).
        self.banner = from_utf8(&stream.split(0x00).next().unwrap()?[..])
	    .or(Err(Error::InvalidHeader))?
            .to_string(); // TODO unwrap
        self.id_size = stream.read_u32::<NetworkEndian>()? as usize;
        // It can be read as u64 as well
        let hi = stream.read_u32::<NetworkEndian>()? as u64;
        let lo = stream.read_u32::<NetworkEndian>()? as u64;
        self.timestamp = (hi << 32) | lo;

        Ok(StreamHprofIterator {
            state: IteratorState::InNormal,
            hprof: self,
            stream,
        })
    }
}

impl<'a, R: Read> StreamHprofIterator<'a, R> {
    fn read_record(&mut self, tag: u8) -> Result<Record, Error> {
        let timestamp_delta: u64 = self.stream.read_u32::<NetworkEndian>()?.into();
        let timestamp = self.hprof.timestamp + timestamp_delta;
        let mut payload_size: usize = self.stream.read_u32::<NetworkEndian>()?.try_into().unwrap();
        if tag == TAG_STRING {
            // TODO: proper Id read
            assert!(self.hprof.id_size == 8);
            let id: Id = (self.stream.read_u64::<NetworkEndian>()? as usize).into();
            payload_size -= self.hprof.id_size;
            // Read string as byte vec.  Contrary to documentation, it
            // is not always a valid utf-8 string.
            let mut data = Vec::<u8>::with_capacity(payload_size);
            data.resize(payload_size, 0);
            self.stream.read_exact(&mut data[..])?;
	    self.hprof.strings.insert(id, data.clone());
            Ok(Record::String(timestamp, id, data))
        } else if tag == TAG_LOAD_CLASS {
            assert!(self.hprof.id_size == 8);

            let serial: u32 = self.stream.read_u32::<NetworkEndian>()?;
            let class_obj_id: Id = (self.stream.read_u64::<NetworkEndian>()? as usize).into();
            let stack_trace_serial: u32 = self.stream.read_u32::<NetworkEndian>()?;
            let class_name_string_id: Id =
                (self.stream.read_u64::<NetworkEndian>()? as usize).into();
            Ok(Record::LoadClass(
                timestamp,
                ClassRecord {
                    serial,
                    class_obj_id,
                    stack_trace_serial,
                    class_name_string_id,
                },
            ))
        } else {
            Err(Error::InvalidPacket(tag, payload_size))
        }
    }

    fn read_data_record(tag: u8, timestamp: Ts, stream: &mut Take<R>) -> Result<Record, Error> {
        let timestamp_delta: u64 = stream.read_u32::<NetworkEndian>()?.into();
        let payload_size: usize = stream.read_u32::<NetworkEndian>()?.try_into().unwrap();
        Err(Error::InvalidPacket(tag, payload_size))
    }
}

impl<'a, R: Read> Iterator for StreamHprofIterator<'a, R> {
    type Item = Result<Record, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match &mut self.state {
                IteratorState::Eof => return None,
                IteratorState::InNormal => {
                    let tag = match self.stream.try_read_u8() {
                        Some(Ok(value)) => value,
                        other => {
                            self.state = IteratorState::Eof;
                            // We have to convert Result<u16, io::Error> to Result<DumpRecord, Error>
                            return other
                                .map(|r| r.map(|_| unreachable!()).or_else(|e| Err(e.into())));
                        }
                    };
                    return match self.read_record(tag) {
                        Ok(v) => Some(Ok(v)),
                        Err(e) => {
                            self.state = IteratorState::Eof;
                            Some(Err(e))
                        }
                    };
                }
                IteratorState::InData(ts, ref mut subreader) => {
                    let ts = *ts;
                    let tag = match subreader.try_read_u8() {
                        None => {
                            // End of data segment
                            self.state = IteratorState::InNormal;
                            continue;
                        }
                        Some(Ok(value)) => value,
                        other => {
                            self.state = IteratorState::Eof;
                            // We have to convert Result<u16, io::Error> to Result<DumpRecord, Error>
                            return other
                                .map(|r| r.map(|_| unreachable!()).or_else(|e| Err(e.into())));
                        }
                    };
                    return Some(Self::read_data_record(tag, ts, subreader));
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
            //eprintln!("{:?}", rec);
        }

        assert!(hprof.timestamp != 0);
        assert!(hprof.id_size == 8 || hprof.id_size == 4); // Any value not equal to 8 is highly unlikely in 2019.
        assert_eq!(hprof.banner, "JAVA PROFILE 1.0.2"); // May suddenly fail if your version will change.

	let mut total_size: usize = 0;
	for (_, v) in hprof.strings {
	    total_size += v.len();
	}
	eprintln!("Data size: {}", total_size);
    }
}
