use crate::decl::*;
use std::io::{self, BufRead, Take};

/// Trait for getting HPROF string (actually, bytes) from source.  It can
/// be &'a [u8] from memory buffer or Vec<u8> read from Read.
pub(crate) trait ReadHprofString<'a> {
    type String;

    /// We use u32 for len as all lengths in HPROF format are u32.
    fn read_string(&mut self, len: u32) -> io::Result<Self::String>;
}

/// Source for memory buffer (be it a mmap'ed data or one read from a file).
#[repr(transparent)]
pub(crate) struct Memory<'a>(pub(crate) &'a [u8]);

impl<'a> ReadHprofString<'a> for Memory<'a> {
    type String = &'a [u8];

    fn read_string(&mut self, len: u32) -> io::Result<&'a [u8]> {
        let len = len as usize;
        if len <= self.0.len() {
            let (result, next) = self.0.split_at(len);
            self.0 = next;
            Ok(result)
        } else {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "not enough data for reading string",
            ))
        }
    }
}

// An implementation that forwards all calls to inner Read instance.
impl<'a> io::Read for Memory<'a> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

// An implementation that forwards all calls to inner BufRead instance.
impl<'a> io::BufRead for Memory<'a> {
    #[inline]
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.0.fill_buf()
    }

    #[inline]
    fn consume(&mut self, amt: usize) {
        self.0.consume(amt)
    }
}

/// Source for a Read stream.
#[repr(transparent)]
pub(crate) struct Stream<R: io::Read>(pub(crate) R);

impl<'a, R: io::BufRead> ReadHprofString<'a> for Stream<R> {
    type String = Vec<u8>;

    fn read_string(&mut self, len: u32) -> io::Result<Vec<u8>> {
        let mut data = vec![0; len as usize];
        self.0.read_exact(&mut data[..])?;
        Ok(data)
    }
}

// An implementation that forwards all calls to inner Read instance.
impl<R: io::Read> io::Read for Stream<R> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

/// An implementation that forwards all calls to inner BufRead instance.
impl<R: io::BufRead> io::BufRead for Stream<R> {
    #[inline]
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.0.fill_buf()
    }

    #[inline]
    fn consume(&mut self, amt: usize) {
        self.0.consume(amt)
    }
}

/// MainState and TakeState are two interconnected states.  The Main
/// means reading from stream without any limits; Take state is used
/// for reading data from segment of known size (the name is inspired
/// by std::io::Take).  The parser switches between them during
/// parsing.  Both methods for switching to another state are
/// consuming.
pub(crate) trait MainState<'a, Take> {
    type Stream: BufRead + ReadHprofString<'a>;

    /// Convert into Take state.
    fn take(self, len: u32) -> Result<Take, Error>;
    /// Access to Reader.
    fn reader(&mut self) -> &mut Self::Stream;
}

pub(crate) trait TakeState<'a, Main> {
    type Stream: BufRead + ReadHprofString<'a>;

    fn into_inner(self) -> Main;
    fn reader(&mut self) -> &mut Self::Stream;
}

pub(crate) struct MainMemory<'a> {
    data: Memory<'a>,
}

impl<'a> MainState<'a, TakeMemory<'a>> for MainMemory<'a> {
    type Stream = Memory<'a>;

    fn take(self, len: u32) -> Result<TakeMemory<'a>, Error> {
        // Assume that usize is not smaller than u32, and
        // conversion is safe.
        use std::mem::size_of;
        static_assert!(size_of::<u32>() <= size_of::<usize>());

        let len = len as usize;
        if len > self.data.0.len() {
            Err(Error::PrematureEOF)
        } else {
            let (prefix, rest) = self.data.0.split_at(len);
            Ok(TakeMemory {
                data: Memory(prefix),
                rest,
            })
        }
    }

    fn reader(&mut self) -> &mut Self::Stream {
        &mut self.data
    }
}

pub(crate) struct TakeMemory<'a> {
    data: Memory<'a>,
    rest: &'a [u8],
}

impl<'a> TakeState<'a, MainMemory<'a>> for TakeMemory<'a> {
    type Stream = Memory<'a>;

    fn into_inner(self) -> MainMemory<'a> {
        MainMemory {
            data: Memory(self.rest),
        }
    }

    fn reader(&mut self) -> &mut Self::Stream {
        &mut self.data
    }
}

pub(crate) struct MainStream<R>(pub(crate) R);

pub(crate) struct TakeStream<R: BufRead>(pub(crate) Stream<Take<R>>);

impl<'a, R: BufRead + ReadHprofString<'a>> MainState<'a, TakeStream<R>> for MainStream<R> {
    type Stream = R;

    fn take(self, len: u32) -> Result<TakeStream<R>, Error> {
        Ok(TakeStream(Stream(self.0.take(len as u64))))
    }

    fn reader(&mut self) -> &mut Self::Stream {
        &mut self.0
    }
}

impl<'a, R: BufRead + ReadHprofString<'a>> TakeState<'a, MainStream<R>> for TakeStream<R> {
    type Stream = Stream<Take<R>>;

    fn into_inner(self) -> MainStream<R> {
        MainStream((self.0).0.into_inner())
    }

    fn reader(&mut self) -> &mut Self::Stream {
        &mut self.0
    }
}
