#![cfg(feature = "der")]

use core::num;
use std::{collections::HashSet, ops::{self, Add, Sub}, vec, mem, iter::{zip, repeat}, cmp};

#[repr(u8)]
pub enum AsnType {
    Boolean(bool) = 0x01,
    Integer(GrowableInteger) = 0x02,
    BitString(AsnBitString) = 0x03,
    OctetString(Vec<u8>) = 0x04,
    Null = 0x05,
    ObjectIdentifier(Oid) = 0x06,
    UTF8String(String) = 0x0C,
    PrintableString(String) = 0x13,
    TeletexString(String) = 0x14,
    IA5String(String) = 0x16,
    BMPString(String) = 0x1E,
    Sequence(Vec<AsnType>) = 0x30,
    Set(HashSet<AsnType>) = 0x31,
}

impl AsnType {
    pub fn serialise(self) -> Vec<u8> {
        use AsnType::*;

        match self {

        Boolean(value) => {
            vec![0x01, 0x01, if value { 0xFF } else { 0x00 }]
        }

        Integer(int) => {
            let length =
                Self::compute_large_length(&int.0);
            vec![vec![0x02], length, int.0].concat()
        }
    
        BitString(bit_string) => {
            let bit_string_bytes = bit_string.to_bytes();
            let mut bytes = vec![0x03];
            bytes.extend(Self::compute_large_length(&bit_string_bytes));
            bytes.extend(bit_string_bytes);
            bytes
        }

        OctetString(octet_string) => {
            let mut bytes = vec![0x04];
            bytes.extend(Self::compute_large_length(&octet_string));
            bytes.extend(octet_string);
            bytes
        }

        Null => {
            vec![0x05, 0x00]
        }

        ObjectIdentifier(oid) => {
            let mut bytes = Vec::new();
            let [first, second] = oid.0[0..=1] else { todo!() };
            bytes.push((first * 40 + second) as u8);
            for number in &oid.0[2..] {
                if *number < 127 {
                    bytes.push(*number as u8);
                    continue;
                }

                bytes.extend(Oid::encode_more_than_127(number));
            }

            let mut result = vec![0x06];
            result.extend(Self::compute_large_length(&bytes));
            result.extend(bytes);

            result
        }

        UTF8String(_) => todo!(),
        PrintableString(_) => todo!(),
        TeletexString(_) => todo!(),
        IA5String(_) => todo!(),
        BMPString(_) => todo!(),

        Sequence(sequence) => {
            let serialised: Vec<_> = sequence.into_iter()
                .flat_map(|item| item.serialise())
                .collect();
            let mut result = vec![0x30];
            result.extend(Self::compute_large_length(&serialised));
            result.extend(serialised);
            
            result
        },

        Set(_) => todo!(),

        }
    }

    fn compute_large_length(bytes: &[u8]) -> Vec<u8> {
        if bytes.len() < 128 {
            vec![bytes.len() as u8]
        } else {
            let length_bytes: Vec<u8> = bytes.len().to_be_bytes()
                .into_iter()
                .skip_while(|byte| *byte == 0x00)
                .collect();
            let length_of_length = length_bytes.len() as u8;
            if length_of_length > 128 { panic!("omg wtf how big is the integer") }
            vec![vec![length_of_length | 0b1000_0000], length_bytes].concat()
        }
    }
}

#[derive(Debug, Clone)]
pub struct AsnBitString {
    pub bits: Vec<u8>,
    pub unused: u8,
}

impl AsnBitString {
    fn to_bytes(mut self) -> Vec<u8> {
        self.bits.insert(0, self.unused);
        self.bits
    }
}

// this struct might get split into a new library, later
#[derive(Debug, Clone)]
pub struct GrowableInteger (pub Vec<u8>);

impl GrowableInteger {
    pub fn from<T: Into<i128>>(number: T) -> Self {
        let large: i128 = number.into();

        let mut result: Vec<u8> = large.to_be_bytes()
            .into_iter()
            .skip_while(|byte| *byte == 0x00)
            .collect();

        if result[0] >= 0x80 {
            result.insert(0, 0x00);
        }

        GrowableInteger(result)
    }

    pub fn back(self) -> Result<i128, ()> {
        if self.0.len() > (128 / 8) { return Err(()) }

        let mut large = 0i128;
        for byte in self.0 {
            // there is a tiny bug 
            large = large.rotate_left(8);
            large |= byte as i128;
        }

        Ok(large)
    }
}

#[inline]
fn zero_extend(collection: Vec<u8>, max: usize) -> Vec<u8> {
    collection.into_iter()
        .rev()
        .chain(repeat(0))
        .take(max)
        .collect()
}

pub struct Oid (pub Vec<u64>);

impl Oid {
    fn encode_more_than_127(number: &u64) -> Vec<u8> {
        let mut result: Vec<u8> = number.to_be_bytes()
            .into_iter()
            .skip_while(|byte| *byte == 0x00)
            .collect();
        for i in 0..result.len() - 1 {
            result[i] <<= 1;
            result[i] |= 0b1000_0000;
            result[i] |= (result[i + 1] & 0b1000_0000) >> 7;
        }

        *result.last_mut().unwrap() &= 0b0111_1111;
        result
    }
}

#[cfg(test)]
mod test {
    use super::AsnType::*;
    use super::*;

    #[test]
    fn bool_true() {
        assert_eq!(Boolean(true).serialise(), vec![0x01, 0x01, 0xFF])
    }

    #[test]
    fn bool_false() {
        assert_eq!(Boolean(false).serialise(), vec![0x01, 0x01, 0x00])
    }

    #[test]
    fn grow_back() {
        assert_eq!(GrowableInteger::from(0xFEDCBA98u32).back().unwrap(), 0xFEDCBA98)
    }

    #[test]
    fn grow_back_err() {
        let large_int = [0x11u8; 32];
        assert_eq!(GrowableInteger(large_int.to_vec()).back(), Err(()));
    }

    #[test]
    fn object_identifier() {
        assert_eq!(ObjectIdentifier(Oid(vec![1, 3, 6, 1, 4, 1, 311, 21, 20])).serialise(),
            [0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x14]);
    }

    #[test]
    fn oid_more_than_127() {
        assert_eq!(Oid::encode_more_than_127(&311), [0x82, 0x37]);
    }

    #[test]
    fn simple_sequence() {
        assert_eq!(Sequence(vec![Integer(GrowableInteger::from(1024)), Null]).serialise(),
            [0x30, 0x06, 0x02, 0x02, 0x04, 0x00, 0x05, 0x00]);
    }

    #[test]
    fn nested_sequence() {
        assert_eq!(Sequence(vec![Sequence(vec![Boolean(false)]), Sequence(vec![Boolean(true)])]).serialise(),
            [0x30, 0x0A, 0x30, 0x03, 0x01, 0x01, 0x00, 0x30, 0x03, 0x01, 0x01, 0xFF]);
    }

    #[test]
    fn int_short() {
        assert_eq!(Integer(GrowableInteger::from(0x10000Eu32)).serialise(),
            vec![0x02, 0x03, 0x10, 0x00, 0x0E])
    }

    #[test]
    fn int_high_order() {
        assert_eq!(Integer(GrowableInteger::from(0x8Fu8)).serialise(),
            vec![0x02, 0x02, 0x00, 0x8F])
    }

    #[test]
    fn int_large() {
        let large_int = [0xAB; 32].to_vec();
        assert_eq!(Integer(GrowableInteger(large_int)).serialise(), vec![
            0x02, 0x20, 
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        ])
    }

    #[test]
    fn int_huge() {
        let huge_int = [0xAB; 256].to_vec();
        assert_eq!(Integer(GrowableInteger(huge_int)).serialise(), vec![
            0x02, 0x82, 0x01, 0x00,
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        ])
    }
}