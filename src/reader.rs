use crate::decl::*;
use std::io::BufRead;


pub(crate) trait MainState<'a> {
    type Take;
    type Stream: BufRead + ReadHprofString<'a>;

    fn take(self, len: usize) -> Result<Self::Take, Error>;
    fn reader(&mut self) -> &mut Self::Stream;
}

pub(crate) trait TakeState<'a> {
    type Main;
    type Stream: BufRead + ReadHprofString<'a>;

    fn into_inner(self) -> Self::Main;
    fn reader(&mut self) -> &mut Self::Stream;
}

pub(crate) struct MainMemory<'a> {
    data: Memory<'a>,
}

impl<'a> MainState<'a> for MainMemory<'a> {
    type Take = TakeMemory<'a>;
    type Stream = Memory<'a>;

    fn take(self, len: usize) -> Result<Self::Take, Error> {
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

impl<'a> TakeState<'a> for TakeMemory<'a> {
    type Main = MainMemory<'a>;
    type Stream = Memory<'a>;

    fn into_inner(self) -> Self::Main {
        MainMemory {
            data: Memory(self.rest),
        }
    }

    fn reader(&mut self) -> &mut Self::Stream {
        &mut self.data
    }

}
