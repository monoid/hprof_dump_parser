use crate::decl::*;
use crate::records::IdReader;
use crate::try_byteorder::ReadBytesTryExt;
use byteorder::{NetworkEndian, ReadBytesExt};
use std::io::{self, Read};

/**
Reader is an abstraction over data stream or memory slice.

While slice can be treated as Read stream, specialized slice
implementation will refer to memory instead of copying HPROF string
data.

While HPROF spec states that String packets contain UTF-8, it is not
always so.  So we keep data as bytes.
*/
pub trait HprofRead<Bytes> {
    fn read_u8(&mut self) -> Result<u8, Error>;
    fn read_i8(&mut self) -> Result<i8, Error>;
    fn read_u16(&mut self) -> Result<u16, Error>;
    fn read_i16(&mut self) -> Result<i16, Error>;
    fn read_u32(&mut self) -> Result<u32, Error>;
    fn read_i32(&mut self) -> Result<i32, Error>;
    fn read_u64(&mut self) -> Result<u64, Error>;
    fn read_i64(&mut self) -> Result<i64, Error>;
    fn read_f32(&mut self) -> Result<f32, Error>;
    fn read_f64(&mut self) -> Result<f64, Error>;
    fn read_id(&mut self) -> Result<Id, Error>;
    /// While HPROF spec states that String packets contain UTF-8, it
    /// is not always so.  So we keep them as bytes.
    // TODO: use crate for "non-utf8" strings.
    fn read_bytes(&mut self, size: u64) -> Result<Bytes, Error>;
    fn skip_data(&mut self, size: u64) -> Result<(), Error>;

    fn skip_array(&mut self, type_: FieldType, count: u64) -> Result<(), Error> {
        self.skip_data(type_.byte_size()? * count)
    }
    // TODO: read arrays

    fn try_read_u8(&mut self) -> Option<Result<u8, Error>>;
    fn try_read_u16(&mut self) -> Option<Result<u16, Error>>;
    // Other try_* are not used
}

trait Taker {
    type TakeType;
    fn take(self) -> Result<Self::TakeType, Error>;
}

trait Untake {
    type UntakeType;
    fn into_inner(self) -> Result<Self::UntakeType, Error>;
}

pub struct TakeBytes<'a, T> {
    data: &'a mut T,
    parent: &'a mut T,
    limit: u64,
}

impl<'a, T> TakeBytes<'a, T> {
    pub fn into_inner(self) -> &'a T {
	self.parent
    }
}

pub struct StreamHprofRead<'a, R: Read + ?Sized> {
    stream: &'a mut R,
    id_reader: IdReader,
}

impl<'a, R: Read> HprofRead<Vec<u8>> for StreamHprofRead<'a, R> {
    fn read_u8(&mut self) -> Result<u8, Error> {
        Ok(self.stream.read_u8()?)
    }

    fn read_i8(&mut self) -> Result<i8, Error> {
        Ok(self.stream.read_i8()?)
    }

    fn read_u16(&mut self) -> Result<u16, Error> {
        Ok(self.stream.read_u16::<NetworkEndian>()?)
    }

    fn read_i16(&mut self) -> Result<i16, Error> {
        Ok(self.stream.read_i16::<NetworkEndian>()?)
    }

    fn read_u32(&mut self) -> Result<u32, Error> {
        Ok(self.stream.read_u32::<NetworkEndian>()?)
    }

    fn read_i32(&mut self) -> Result<i32, Error> {
        Ok(self.stream.read_i32::<NetworkEndian>()?)
    }

    fn read_u64(&mut self) -> Result<u64, Error> {
        Ok(self.stream.read_u64::<NetworkEndian>()?)
    }

    fn read_i64(&mut self) -> Result<i64, Error> {
        Ok(self.stream.read_i64::<NetworkEndian>()?)
    }

    fn read_f32(&mut self) -> Result<f32, Error> {
        Ok(self.stream.read_f32::<NetworkEndian>()?)
    }

    fn read_f64(&mut self) -> Result<f64, Error> {
        Ok(self.stream.read_f64::<NetworkEndian>()?)
    }

    fn read_id(&mut self) -> Result<Id, Error> {
        self.id_reader.read_id(self.stream)
    }

    fn read_bytes(&mut self, size: u64) -> Result<Vec<u8>, Error> {
        let mut res = vec![0u8; size as usize]; // TODO TryInto
        self.stream.read_exact(&mut *res)?;
        Ok(res)
    }

    fn skip_data(&mut self, size: u64) -> Result<(), Error> {
        let copied = io::copy(&mut self.stream.take(size), &mut io::sink())?;
        if copied < size {
            Err(Error::PrematureEOF)
        } else {
            Ok(())
        }
    }

    fn try_read_u8(&mut self) -> Option<Result<u8, Error>> {
        self.stream.try_read_u8().map(|r| r.map_err(Into::into))
    }

    fn try_read_u16(&mut self) -> Option<Result<u16, Error>> {
        self.stream
            .try_read_u16::<NetworkEndian>()
            .map(|r| r.map_err(Into::into))
    }
}

pub struct MemoryHprofRead<'a> {
    buffer: &'a [u8],
    id_reader: IdReader,
}

impl<'a> HprofRead<&'a [u8]> for MemoryHprofRead<'a> {
    fn read_u8(&mut self) -> Result<u8, Error> {
        Ok(self.buffer.read_u8()?)
    }

    fn read_i8(&mut self) -> Result<i8, Error> {
        Ok(self.buffer.read_i8()?)
    }

    fn read_u16(&mut self) -> Result<u16, Error> {
        Ok(self.buffer.read_u16::<NetworkEndian>()?)
    }

    fn read_i16(&mut self) -> Result<i16, Error> {
        Ok(self.buffer.read_i16::<NetworkEndian>()?)
    }

    fn read_u32(&mut self) -> Result<u32, Error> {
        Ok(self.buffer.read_u32::<NetworkEndian>()?)
    }

    fn read_i32(&mut self) -> Result<i32, Error> {
        Ok(self.buffer.read_i32::<NetworkEndian>()?)
    }

    fn read_u64(&mut self) -> Result<u64, Error> {
        Ok(self.buffer.read_u64::<NetworkEndian>()?)
    }

    fn read_i64(&mut self) -> Result<i64, Error> {
        Ok(self.buffer.read_i64::<NetworkEndian>()?)
    }

    fn read_f32(&mut self) -> Result<f32, Error> {
        Ok(self.buffer.read_f32::<NetworkEndian>()?)
    }

    fn read_f64(&mut self) -> Result<f64, Error> {
        Ok(self.buffer.read_f64::<NetworkEndian>()?)
    }

    fn read_id(&mut self) -> Result<Id, Error> {
        self.id_reader.read_id(&mut self.buffer)
    }

    fn read_bytes(&mut self, size: u64) -> Result<&'a [u8], Error> {
        let us = size as usize; // TODO TryInto
        if self.buffer.len() < us {
            self.buffer = &self.buffer[..0];
            Err(Error::PrematureEOF)
        } else {
            let (res, new_buf) = self.buffer.split_at(us);
            self.buffer = new_buf;
            Ok(res)
        }
    }

    fn skip_data(&mut self, size: u64) -> Result<(), Error> {
        let us = size as usize;
        if self.buffer.len() < us {
            Err(Error::PrematureEOF)
        } else {
            self.buffer = &self.buffer[us..];
            Ok(())
        }
    }

    fn try_read_u8(&mut self) -> Option<Result<u8, Error>> {
        self.buffer.try_read_u8().map(|r| r.map_err(Into::into))
    }

    fn try_read_u16(&mut self) -> Option<Result<u16, Error>> {
        self.buffer
            .try_read_u16::<NetworkEndian>()
            .map(|r| r.map_err(Into::into))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_stream_read() {
        let data = vec![1u8, 0u8];
        let mut reader = StreamHprofRead {
            stream: &mut &*data,
            id_reader: IdReader::new(),
        };
        let data_16 = reader.read_u16().unwrap();
        let none_data_16 = reader.try_read_u16();

        assert_eq!(data_16, 256);
        assert!(none_data_16.is_none());
    }

    #[test]
    fn test_stream_string() {
        let data = vec![1u8, 0u8];
        let mut reader = StreamHprofRead {
            stream: &mut &*data,
            id_reader: IdReader::new(),
        };
        let data_str = reader.read_bytes(2).unwrap();

        assert_eq!(data_str, data);
    }

    #[test]
    fn test_string_string_eof() {
        let data = vec![1u8, 0u8];
        let mut reader = StreamHprofRead {
            stream: &mut &*data,
            id_reader: IdReader::new(),
        };
        let data_res = reader.read_bytes(3);

        assert!(data_res.is_err());
    }

    #[test]
    fn test_memory_read() {
        let data = vec![1u8, 0u8];
        let mut reader = MemoryHprofRead {
            buffer: &mut &*data,
            id_reader: IdReader::new(),
        };
        let data_16 = reader.read_u16().unwrap();
        let none_data_16 = reader.try_read_u16();

        assert_eq!(data_16, 256);
        assert!(none_data_16.is_none());
    }

    #[test]
    fn test_memory_read_incomplete() {
        let data = vec![1u8];
        let mut reader = MemoryHprofRead {
            buffer: &mut &*data,
            id_reader: IdReader::new(),
        };
        let data_res = reader.read_u16();

        assert!(data_res.is_err());
    }

    #[test]
    fn test_memory_string() {
        let data = vec![1u8, 0u8];
        let mut reader = MemoryHprofRead {
            buffer: &mut &*data,
            id_reader: IdReader::new(),
        };
        let data_str = reader.read_bytes(2).unwrap();

        assert_eq!(data_str, &*data);
    }

    #[test]
    fn test_memory_string_eof() {
        let data = vec![1u8, 0u8];
        let mut reader = MemoryHprofRead {
            buffer: &mut &*data,
            id_reader: IdReader::new(),
        };

        let data_res = reader.read_bytes(3);
        assert!(data_res.is_err());

        // Make sure no data is left in the stream:
        let try_bytes = reader.try_read_u8();
        assert!(try_bytes.is_none());
    }
}
