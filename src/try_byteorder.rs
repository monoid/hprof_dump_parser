use byteorder::ByteOrder;
use std::io;

/// Methods of this trait try to read a number from the stream; if
/// there is no data (EOF), they return None; otherwise they return
/// Option<std::io::Result<...>>.  So, if you read u16, if there is 0
/// bytes in the stream, None is returned.  If there is 1 byte, it is
/// Some(Err(...)).  And if there are 2 bytes, it is Some(Ok(value)).
/// So, you may both detect EOF and get error info.
pub trait ReadBytesTryExt: io::Read {
    /// Current implementation returns None if buffer size is 0.  It
    /// may change to Some(Ok(())) in a future.
    fn try_read_exact(&mut self, mut buf: &mut [u8]) -> Option<io::Result<()>> {
        // Implementation is base on Read::read_exact from std.
        loop {
            // Loop while not interrupted
            match self.read(buf) {
                Ok(0) => return None,
                Ok(size) => {
                    let tmp = buf;
                    buf = &mut tmp[size..];
                    break;
                }
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {
                    continue;
                }
                Err(e) => return Some(Err(e)),
            };
        }
        // Ditto
        while !buf.is_empty() {
            match self.read(buf) {
                Ok(0) => break,
                Ok(n) => {
                    let tmp = buf;
                    buf = &mut tmp[n..];
                }
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Some(Err(e)),
            }
        }
        return Some(if !buf.is_empty() {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "failed to fill whole buffer",
            ))
        } else {
            Ok(())
        });
    }

    fn try_read_u8(&mut self) -> Option<io::Result<u8>> {
        let mut buf = [0; 1];
        self.try_read_exact(&mut buf).map(|r| r.map(|_| buf[0]))
    }

    fn try_read_i8(&mut self) -> Option<io::Result<i8>> {
        let mut buf = [0; 1];
        self.try_read_exact(&mut buf)
            .map(|r| r.map(|_| buf[0] as i8))
    }

    fn try_read_u16<T: ByteOrder>(&mut self) -> Option<io::Result<u16>> {
        let mut buf = [0; 2];
        self.try_read_exact(&mut buf)
            .map(|r| r.map(|_| T::read_u16(&buf)))
    }

    fn try_read_i16<T: ByteOrder>(&mut self) -> Option<io::Result<i16>> {
        let mut buf = [0; 2];
        self.try_read_exact(&mut buf)
            .map(|r| r.map(|_| T::read_i16(&buf)))
    }

    fn try_read_u32<T: ByteOrder>(&mut self) -> Option<io::Result<u32>> {
        let mut buf = [0; 4];
        self.try_read_exact(&mut buf)
            .map(|r| r.map(|_| T::read_u32(&buf)))
    }

    fn try_read_i32<T: ByteOrder>(&mut self) -> Option<io::Result<i32>> {
        let mut buf = [0; 4];
        self.try_read_exact(&mut buf)
            .map(|r| r.map(|_| T::read_i32(&buf)))
    }

    fn try_read_u64<T: ByteOrder>(&mut self) -> Option<io::Result<u64>> {
        let mut buf = [0; 8];
        self.try_read_exact(&mut buf)
            .map(|r| r.map(|_| T::read_u64(&buf)))
    }
    fn try_read_i64<T: ByteOrder>(&mut self) -> Option<io::Result<i64>> {
        let mut buf = [0; 8];
        self.try_read_exact(&mut buf)
            .map(|r| r.map(|_| T::read_i64(&buf)))
    }
}

impl<R: io::Read> ReadBytesTryExt for R {}

#[cfg(test)]
mod tests {
    use super::ReadBytesTryExt;
    use byteorder::{BigEndian, LittleEndian};
    use std::io::{Cursor, ErrorKind};

    #[test]
    fn test_try_read_exact_empty0() {
        let data = [0; 0];
        let mut buf = [0; 0];
        let mut cur = Cursor::new(&data);
        // It is debatable, but it is how it is yet.
        assert!(cur.try_read_exact(&mut buf).is_none());
    }

    #[test]
    fn test_try_read_exact_empty1() {
        let data = [0; 0];
        let mut buf = [0; 1];
        let mut cur = Cursor::new(&data);
        assert!(cur.try_read_exact(&mut buf).is_none());
    }

    #[test]
    fn test_try_read_exact_empty2() {
        let data = [0; 0];
        let mut buf = [0; 2];
        let mut cur = Cursor::new(&data);
        assert!(cur.try_read_exact(&mut buf).is_none());
    }

    #[test]
    fn test_try_read_exact_incomplete1() {
        let data = [10; 1];
        let mut buf = [0; 2];
        let mut cur = Cursor::new(&data);
        let ret = cur
            .try_read_exact(&mut buf)
            .map(|res| res.map_err(|e| e.kind()));
        assert_eq!(ret, Some(Err(ErrorKind::UnexpectedEof)));
    }

    #[test]
    fn test_try_read_exact_complete2() {
        let data = [10; 2];
        let mut buf = [0; 2];
        let mut cur = Cursor::new(&data);
        let ret = cur
            .try_read_exact(&mut buf)
            .map(|res| res.map_err(|e| e.kind()));
        assert_eq!(ret, Some(Ok(())));
    }

    #[test]
    fn test_try_read_u8_empty() {
        let data = [0; 0];
        let mut cur = Cursor::new(&data);
        let ret = cur.try_read_u8().map(|res| res.map_err(|e| e.kind()));
        assert_eq!(ret, None);
    }

    #[test]
    fn test_try_read_u8_1() {
        let data = [10; 1];
        let mut cur = Cursor::new(&data);
        let ret = cur.try_read_u8().map(|res| res.map_err(|e| e.kind()));
        assert_eq!(ret, Some(Ok(10)));
    }

    #[test]
    fn test_try_read_u8_2() {
        let data = [10, 11];
        let mut cur = Cursor::new(&data);
        let ret = cur.try_read_u8().map(|res| res.map_err(|e| e.kind()));
        assert_eq!(ret, Some(Ok(10)));
    }

    #[test]
    fn test_try_read_i8_empty() {
        let data = [0; 0];
        let mut cur = Cursor::new(&data);
        let ret = cur.try_read_i8().map(|res| res.map_err(|e| e.kind()));
        assert_eq!(ret, None);
    }

    #[test]
    fn test_try_read_i8_1() {
        let data = [10; 1];
        let mut cur = Cursor::new(&data);
        let ret = cur.try_read_i8().map(|res| res.map_err(|e| e.kind()));
        assert_eq!(ret, Some(Ok(10)));
    }

    #[test]
    fn test_try_read_i8_2() {
        let data = [10, 11];
        let mut cur = Cursor::new(&data);
        let ret = cur.try_read_i8().map(|res| res.map_err(|e| e.kind()));
        assert_eq!(ret, Some(Ok(10)));
    }

    #[test]
    fn test_try_read_u16_0() {
        let data = [0; 0];
        let mut cur = Cursor::new(&data);
        let ret = cur
            .try_read_u16::<BigEndian>()
            .map(|res| res.map_err(|e| e.kind()));
        assert_eq!(ret, None);
    }

    #[test]
    fn test_try_read_u16_1() {
        let data = [10; 1];
        let mut cur = Cursor::new(&data);
        let ret = cur
            .try_read_u16::<BigEndian>()
            .map(|res| res.map_err(|e| e.kind()));
        assert_eq!(ret, Some(Err(ErrorKind::UnexpectedEof)));
    }

    #[test]
    fn test_try_read_u16_2be() {
        let data = [0x1F, 0xF1];
        let mut cur = Cursor::new(&data);
        let ret = cur
            .try_read_u16::<BigEndian>()
            .map(|res| res.map_err(|e| e.kind()));
        assert_eq!(ret, Some(Ok(0x1FF1)));
    }

    #[test]
    fn test_try_read_u16_2le() {
        let data = [0x1F, 0xF1];
        let mut cur = Cursor::new(&data);
        let ret = cur
            .try_read_u16::<LittleEndian>()
            .map(|res| res.map_err(|e| e.kind()));
        assert_eq!(ret, Some(Ok(0xF11F)));
    }

    #[test]
    fn test_try_read_u32_0() {
        let data = [0; 0];
        let mut cur = Cursor::new(&data);
        let ret = cur
            .try_read_u32::<BigEndian>()
            .map(|res| res.map_err(|e| e.kind()));
        assert_eq!(ret, None);
    }

    #[test]
    fn test_try_read_u32_2() {
        let data = [10; 2];
        let mut cur = Cursor::new(&data);
        let ret = cur
            .try_read_u32::<BigEndian>()
            .map(|res| res.map_err(|e| e.kind()));
        assert_eq!(ret, Some(Err(ErrorKind::UnexpectedEof)));
    }

    #[test]
    fn test_try_read_u32_4be() {
        let data = [0x11, 0x22, 0x33, 0x44];
        let mut cur = Cursor::new(&data);
        let ret = cur
            .try_read_u32::<BigEndian>()
            .map(|res| res.map_err(|e| e.kind()));
        assert_eq!(ret, Some(Ok(0x11223344)));
    }

    #[test]
    fn test_try_read_u32_4le() {
        let data = [0x11, 0x22, 0x33, 0x44];
        let mut cur = Cursor::new(&data);
        let ret = cur
            .try_read_u32::<LittleEndian>()
            .map(|res| res.map_err(|e| e.kind()));
        assert_eq!(ret, Some(Ok(0x44332211)));
    }

    #[test]
    fn test_try_read_u64_0() {
        let data = [0; 0];
        let mut cur = Cursor::new(&data);
        let ret = cur
            .try_read_u64::<BigEndian>()
            .map(|res| res.map_err(|e| e.kind()));
        assert_eq!(ret, None);
    }

    #[test]
    fn test_try_read_u64_2() {
        let data = [10; 2];
        let mut cur = Cursor::new(&data);
        let ret = cur
            .try_read_u64::<BigEndian>()
            .map(|res| res.map_err(|e| e.kind()));
        assert_eq!(ret, Some(Err(ErrorKind::UnexpectedEof)));
    }

    #[test]
    fn test_try_read_u64_7be() {
        let data = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let mut cur = Cursor::new(&data);
        let ret = cur
            .try_read_u64::<BigEndian>()
            .map(|res| res.map_err(|e| e.kind()));
        assert_eq!(ret, Some(Err(ErrorKind::UnexpectedEof)));
    }

    #[test]
    fn test_try_read_u64_8be() {
        let data = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let mut cur = Cursor::new(&data);
        let ret = cur
            .try_read_u64::<BigEndian>()
            .map(|res| res.map_err(|e| e.kind()));
        assert_eq!(ret, Some(Ok(0x1122334455667788)));
    }

    #[test]
    fn test_try_read_u64_8le() {
        let data = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let mut cur = Cursor::new(&data);
        let ret = cur
            .try_read_u64::<LittleEndian>()
            .map(|res| res.map_err(|e| e.kind()));
        assert_eq!(ret, Some(Ok(0x8877665544332211)));
    }

    #[test]
    fn test_try_read_i16_0() {
        let data = [0; 0];
        let mut cur = Cursor::new(&data);
        let ret = cur
            .try_read_i16::<BigEndian>()
            .map(|res| res.map_err(|e| e.kind()));
        assert_eq!(ret, None);
    }

    #[test]
    fn test_try_read_i16_1() {
        let data = [10; 1];
        let mut cur = Cursor::new(&data);
        let ret = cur
            .try_read_i16::<BigEndian>()
            .map(|res| res.map_err(|e| e.kind()));
        assert_eq!(ret, Some(Err(ErrorKind::UnexpectedEof)));
    }

    #[test]
    fn test_try_read_i16_2be() {
        let data = [0x1F, 0xF1];
        let mut cur = Cursor::new(&data);
        let ret = cur
            .try_read_i16::<BigEndian>()
            .map(|res| res.map_err(|e| e.kind()));
        assert_eq!(ret, Some(Ok(0x1FF1)));
    }

    #[test]
    fn test_try_read_i16_2le() {
        let data = [0x1F, 0x71];
        let mut cur = Cursor::new(&data);
        let ret = cur
            .try_read_i16::<LittleEndian>()
            .map(|res| res.map_err(|e| e.kind()));
        assert_eq!(ret, Some(Ok(0x711F)));
    }

    #[test]
    fn test_try_read_i16_2le_neg() {
        let data = [0x1F, 0xF1];
        let mut cur = Cursor::new(&data);
        let ret = cur
            .try_read_i16::<LittleEndian>()
            .map(|res| res.map_err(|e| e.kind()));
        assert_eq!(ret, Some(Ok(-3809)));
    }

    #[test]
    fn test_try_read_i32_0() {
        let data = [0; 0];
        let mut cur = Cursor::new(&data);
        let ret = cur
            .try_read_i32::<BigEndian>()
            .map(|res| res.map_err(|e| e.kind()));
        assert_eq!(ret, None);
    }

    #[test]
    fn test_try_read_i32_2() {
        let data = [10; 2];
        let mut cur = Cursor::new(&data);
        let ret = cur
            .try_read_i32::<BigEndian>()
            .map(|res| res.map_err(|e| e.kind()));
        assert_eq!(ret, Some(Err(ErrorKind::UnexpectedEof)));
    }

    #[test]
    fn test_try_read_i32_4be() {
        let data = [0x11, 0x22, 0x33, 0x44];
        let mut cur = Cursor::new(&data);
        let ret = cur
            .try_read_i32::<BigEndian>()
            .map(|res| res.map_err(|e| e.kind()));
        assert_eq!(ret, Some(Ok(0x11223344)));
    }

    #[test]
    fn test_try_read_i32_4le() {
        let data = [0x11, 0x22, 0x33, 0x44];
        let mut cur = Cursor::new(&data);
        let ret = cur
            .try_read_i32::<LittleEndian>()
            .map(|res| res.map_err(|e| e.kind()));
        assert_eq!(ret, Some(Ok(0x44332211)));
    }

    #[test]
    fn test_try_read_i64_0() {
        let data = [0; 0];
        let mut cur = Cursor::new(&data);
        let ret = cur
            .try_read_i64::<BigEndian>()
            .map(|res| res.map_err(|e| e.kind()));
        assert_eq!(ret, None);
    }

    #[test]
    fn test_try_read_i64_2() {
        let data = [10; 2];
        let mut cur = Cursor::new(&data);
        let ret = cur
            .try_read_i64::<BigEndian>()
            .map(|res| res.map_err(|e| e.kind()));
        assert_eq!(ret, Some(Err(ErrorKind::UnexpectedEof)));
    }

    #[test]
    fn test_try_read_i64_7be() {
        let data = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let mut cur = Cursor::new(&data);
        let ret = cur
            .try_read_i64::<BigEndian>()
            .map(|res| res.map_err(|e| e.kind()));
        assert_eq!(ret, Some(Err(ErrorKind::UnexpectedEof)));
    }

    #[test]
    fn test_try_read_i64_8be() {
        let data = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let mut cur = Cursor::new(&data);
        let ret = cur
            .try_read_i64::<BigEndian>()
            .map(|res| res.map_err(|e| e.kind()));
        assert_eq!(ret, Some(Ok(0x1122334455667788)));
    }

    #[test]
    fn test_try_read_i64_8le() {
        let data = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x78];
        let mut cur = Cursor::new(&data);
        let ret = cur
            .try_read_i64::<LittleEndian>()
            .map(|res| res.map_err(|e| e.kind()));
        assert_eq!(ret, Some(Ok(0x7877665544332211)));
    }

    #[test]
    fn test_try_read_i64_8le_neg() {
        let data = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let mut cur = Cursor::new(&data);
        let ret = cur
            .try_read_i64::<LittleEndian>()
            .map(|res| res.map_err(|e| e.kind()));
        assert_eq!(ret, Some(Ok(-8613303245920329199)));
    }
}
