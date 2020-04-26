use crate::decl::*;
use std::io::{BufRead, Take};


pub trait MainState<'a> {
    type Take;
    type Stream: BufRead + ReadHprofString<'a>;

    fn take(self, len: usize) -> Result<Self::Take, Error>;
    fn reader(&mut self) -> &mut Self::Stream;
}

pub trait TakeState<'a> {
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

pub struct MainStream<R>(pub(crate) R);

pub struct TakeStream<R: BufRead>(pub(crate) Stream<Take<R>>);


impl<'a, R: BufRead + ReadHprofString<'a>> MainState<'a> for MainStream<R> {
    type Take = TakeStream<R>;
    type Stream = R;

    fn take(self, len: usize) -> Result<Self::Take, Error> {
        Ok(TakeStream(Stream(self.0.take(len as u64))))
    }

    fn reader(&mut self) -> &mut Self::Stream {
        &mut self.0
    }
}

impl<'a, R: BufRead + ReadHprofString<'a>> TakeState<'a> for TakeStream<R> {
    type Main = MainStream<R>;
    type Stream = Stream<Take<R>>;

    fn into_inner(self) -> Self::Main {
        MainStream((self.0).0.into_inner())
    }

    fn reader(&mut self) -> &mut Self::Stream {
        &mut self.0
    }

}
