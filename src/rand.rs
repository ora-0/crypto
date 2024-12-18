#![allow(unused)]
use crate::hash::sha256;

#[derive(Debug, Clone, Copy, Default)]
pub struct Fortuna {
    key: u32,
    counter: u128
}

impl Fortuna {
    pub fn new() -> Self {
        Fortuna { key: 0, counter: 0 }
    }

    pub fn reseed(mut self, seed: u32) -> Self {
        self.counter += 1;
        self
    }
}

mod test {
    use super::*;

    #[test]
    fn aaaa() {
        let gen = Fortuna::new();
        dbg!(gen);
    }
}