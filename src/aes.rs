#![cfg(feature = "aes")]

use std::iter::zip;
include!("aes_consts.rs"); // imports SBOX, RIJNDAEL_MATRIX, and RCON

fn pad(message: &[u8]) -> Vec<u8> {
    let mut padded = message.to_vec();
    let padding_length = message.len() % 16;

    padded.resize(message.len() + padding_length, 0);

    padded
}

/// multiplies by two, within GF(2^8)
fn mul_2(a: u8) -> u8 {
    if a >> 7 == 1 { a << 1 ^ 0b0001_1011 }
    else { a << 1 }
}

/// multiplies by three, within GF(2^8)
fn mul_3(a: u8) -> u8 {
    mul_2(a) ^ a
}

/// multiplies by 9, within GF(2^8)
fn mul_9(a: u8) -> u8 {
    mul_2(mul_2(mul_2(a))) ^ a
}

/// multiplies by 11, within GF(2^8)
fn mul_11(a: u8) -> u8 {
    mul_2(mul_2(mul_2(a))) ^ mul_3(a)
}

/// multiplies by 13, within GF(2^8)
fn mul_13(a: u8) -> u8 {
    mul_2(mul_2(mul_2(a))) ^ mul_2(mul_2(a)) ^ a
}

/// multiplies by 14, within GF(2^8)
fn mul_14(a: u8) -> u8 {
    mul_2(mul_2(mul_2(a))) ^ mul_2(mul_2(a)) ^ mul_2(a)
}

const NR: usize = 10;
const NK: usize = 4;

pub fn cipher_block(chunk: &[u8], key: [u8; 16]) -> Vec<u8> {
    let expanded_key = key_expansion(key);
    let mut state: Vec<u8> = add_vectors(chunk, &expanded_key[0]);

    for round_key in &expanded_key[1..NR] {
        state = sub_bytes(state);
        state = shift_rows(state);
        state = mix_columns(state);
        state = add_vectors(&state, round_key);
    }

    state = shift_rows(state);
    state = sub_bytes(state);
    state = add_vectors(&state, &expanded_key[NR]);
    state
}

fn sub_bytes(state: Vec<u8>) -> Vec<u8> {
    state.iter()
        .map(|b| SBOX[(b >> 4) as usize][(b & 0x0F) as usize]) // as usize vebosity
        .collect()
}

fn shift_rows(mut state: Vec<u8>) -> Vec<u8> {
    for i in 0..4 {
        let mut a = get_row(&state, i);
        a.rotate_left(i);
        state = change_row(state, &a, i);
    }

    state
}

fn mix_columns(mut state: Vec<u8>) -> Vec<u8> {
    for j in (0..16).step_by(4) {
        let [a, b, c, d] = state[j..j+4] else { unreachable!() };

        // performs the matrix transform (aka multiply)
        state[j]   = mul_2(a) ^ mul_3(b) ^ c ^ d;
        state[j+1] = a ^ mul_2(b) ^ mul_3(c) ^ d;
        state[j+2] = a ^ b ^ mul_2(c) ^ mul_3(d);
        state[j+3] = mul_3(a) ^ b ^ c ^ mul_2(d);
    }
    state
}

fn add_vectors(a: &[u8], b: &[u8]) -> Vec<u8> {
    zip(a, b).map(|(a, b)| a ^ b).collect()
}

fn key_expansion(key: [u8; 16]) -> Vec<Vec<u8>> {
    let mut blocks = vec![key.to_vec()];
    blocks.reserve_exact(10);
    for item in &RCON {
        let previous_block = blocks.last().unwrap().to_vec();

        // first special case
        let mut w_minus_1 = sub_bytes(previous_block[12..16].to_vec());
        w_minus_1.rotate_left(1);
        let w_minus_4 = previous_block[0..4].iter();
        let mut working_block: Vec<_> = zip(zip(w_minus_1, w_minus_4), item)
            .map(|((a, b), c)| a ^ b ^ c)
            .collect();

        // rest
        for j in (4..16).step_by(4) {
            let w_minus_1 = working_block[working_block.len() - 4..].iter();
            let w_minus_3 = previous_block[j..j+4].iter();
            
            // can be simplified in the future with the `extend` method instead of `append`
            // currently, it causes an error, but will be fixed with the polonius borrow checker
            let mut xored = zip(w_minus_1, w_minus_3).map(|(a, b)| a ^ b).collect();
            working_block.append(&mut xored);
        }
        
        blocks.push(working_block); 
    }

    blocks
}

fn inv_cipher_block(chunk: &[u8], key: [u8; 16]) -> Vec<u8> {
    let expanded_key = key_expansion(key);
    
    let mut state = add_vectors(chunk, &expanded_key[NR]);
    state = inv_sub_bytes(state);
    state = inv_shift_rows(state);

    for i in (1..NR).rev() {
        state = add_vectors(&state, &expanded_key[i]);
        state = inv_mix_columns(state);
        state = inv_sub_bytes(state);
        state = inv_shift_rows(state);
    }

    state = add_vectors(&state, &expanded_key[0]);

    state
}

fn inv_sub_bytes(state: Vec<u8>) -> Vec<u8> {
    state.iter()
        .map(|b| INV_SBOX[(b >> 4) as usize][(b & 0x0F) as usize]) // as usize verbosity
        .collect()
}

fn inv_shift_rows(mut state: Vec<u8>) -> Vec<u8> {
    for i in 0..4 {
        let mut a = get_row(&state, i);
        a.rotate_right(i);
        state = change_row(state, &a, i);
    }

    state
}

fn inv_mix_columns(mut state: Vec<u8>) -> Vec<u8> {
    for j in (0..16).step_by(4) {
        let [a, b, c, d] = state[j..j+4] else { unreachable!() };

        // performs the matrix transform (aka multiply)
        state[j]   = mul_14(a) ^ mul_11(b) ^ mul_13(c) ^ mul_9(d);
        state[j+1] = mul_9(a)  ^ mul_14(b) ^ mul_11(c) ^ mul_13(d);
        state[j+2] = mul_13(a) ^ mul_9(b)  ^ mul_14(c) ^ mul_11(d);
        state[j+3] = mul_11(a) ^ mul_13(b) ^ mul_9(c)  ^ mul_14(d);
    }
    state
}

fn get_row<T: Copy>(vec: &[T], index: usize) -> [T; 4] {
    [vec[index], vec[4+index], vec[4*2+index], vec[4*3+index]]
}

/// this function is pure, relying on assignments instead of mutations
fn change_row<T: Copy>(mut vec: Vec<T>, contents: &[T], index: usize) -> Vec<T> {
    vec[index]       = contents[0];
    vec[4 + index]   = contents[1];
    vec[4*2 + index] = contents[2];
    vec[4*3 + index] = contents[3];
    vec
}

pub fn cipher_cfb(message: &[u8], key: [u8; 16], init_vector: [u8; 16]) -> Vec<u8> {
    let padded = pad(message);
    let mut acc = Vec::with_capacity(padded.len());
    let mut last_ciphertext: &[_] = &init_vector;

    for chunk in padded.chunks(16) {
        let cipher = add_vectors(&cipher_block(last_ciphertext, key), chunk);
        acc.extend(cipher);
        last_ciphertext = &acc[acc.len() - 16..];
    }
    acc
}

pub fn cipher_cbc(message: &[u8], key: [u8; 16], init_vector: [u8; 16]) -> Vec<u8> {
    let padded = pad(message);
    let mut acc = Vec::with_capacity(padded.len());
    let mut last_ciphertext: &[_] = &init_vector;

    for chunk in padded.chunks(16) {
        let cipher = cipher_block(&add_vectors(chunk, last_ciphertext), key);
        acc.extend(cipher);
        last_ciphertext = &acc[acc.len() - 16..];
    }
    acc
}

pub fn cipher_ecb(message: &[u8], key: [u8; 16]) -> Vec<u8> {
    let padded = pad(message);
    padded.chunks(16).flat_map(|chunk| cipher_block(chunk, key)).collect()
}

fn to_hex(message: &[u8]) -> String {
    message.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_column_gets_the_column() {
        let t = vec![0, 1, 0, 0,
                     2, 1, 2, 2,
                     3, 1, 3, 3,
                     4, 1, 4, 4];
        assert_eq!(get_row(&t, 1), [1, 1, 1, 1]);
    }

    #[test]
    fn change_column_changes_the_column() {
        let t = change_row([0; 16].to_vec(), &[1, 2, 3, 4], 3);
        assert_eq!(get_row(&t, 3), [1, 2, 3, 4]);
    }

    #[test]
    fn mul_2_works() {
        assert_eq!(mul_2(0x57), 0xae);
    }

    #[test]
    fn mul_2_works_with_b7_bit_set() {
        assert_eq!(mul_2(0x8e), 0x07);
    }

    #[test]
    fn mul_11_works() {
        assert_eq!(mul_11(0x37), 0xFA);
    }

    #[test]
    fn mul_13_works() {
        assert_eq!(mul_13(0x94), 0x3E);
    }

    #[test]
    fn mul_14_works() {
        assert_eq!(mul_14(0x47), 0x87);
    }

    #[test]
    fn cipher_block_works() {
        let key = [0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C];
        let mut input = [0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A];

        let ciphertext = to_hex(&cipher_block(&input, key));
        assert_eq!(ciphertext, "3ad77bb40d7a3660a89ecaf32466ef97");
    }

    #[test]
    fn inv_cipher_block_works() {
        let key = [0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C];
        let mut input = [0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60, 0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66, 0xEF, 0x97];

        let ciphertext = inv_cipher_block(&input, key);
        assert_eq!(ciphertext, [0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A]);
    }

    #[test]
    fn ecb_block_works() {
        let key = [0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C];
        let mut input = [
            0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
            0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
            0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
            0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10,
        ];
        let expected = [
            0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60, 0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66, 0xEF, 0x97,
            0xF5, 0xD3, 0xD5, 0x85, 0x03, 0xB9, 0x69, 0x9D, 0xE7, 0x85, 0x89, 0x5A, 0x96, 0xFD, 0xBA, 0xAF,
            0x43, 0xB1, 0xCD, 0x7F, 0x59, 0x8E, 0xCE, 0x23, 0x88, 0x1B, 0x00, 0xE3, 0xED, 0x03, 0x06, 0x88,
            0x7B, 0x0C, 0x78, 0x5E, 0x27, 0xE8, 0xAD, 0x3F, 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5D, 0xD4,
        ];

        assert_eq!(cipher_ecb(&input, key), expected);
    }

    #[test]
    fn cbc_block_works() {
        let key = [0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C];
        let init_vector = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let mut input = [
            0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
            0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
            0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
            0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10,
        ];
        let expected = [
            0x76, 0x49, 0xAB, 0xAC, 0x81, 0x19, 0xB2, 0x46, 0xCE, 0xE9, 0x8E, 0x9B, 0x12, 0xE9, 0x19, 0x7D, 
            0x50, 0x86, 0xCB, 0x9B, 0x50, 0x72, 0x19, 0xEE, 0x95, 0xDB, 0x11, 0x3A, 0x91, 0x76, 0x78, 0xB2, 
            0x73, 0xBE, 0xD6, 0xB8, 0xE3, 0xC1, 0x74, 0x3B, 0x71, 0x16, 0xE6, 0x9E, 0x22, 0x22, 0x95, 0x16, 
            0x3F, 0xF1, 0xCA, 0xA1, 0x68, 0x1F, 0xAC, 0x09, 0x12, 0x0E, 0xCA, 0x30, 0x75, 0x86, 0xE1, 0xA7,
        ];

        assert_eq!(cipher_cbc(&input, key, init_vector), expected);
    }

    #[test]
    fn cfb_block_works() {
        let key = [0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C];
        let init_vector = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let mut input = [
            0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
            0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
            0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
            0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10,
        ];
        let expected = [
            0x3B, 0x3F, 0xD9, 0x2E, 0xB7, 0x2D, 0xAD, 0x20, 0x33, 0x34, 0x49, 0xF8, 0xE8, 0x3C, 0xFB, 0x4A,  
            0xC8, 0xA6, 0x45, 0x37, 0xA0, 0xB3, 0xA9, 0x3F, 0xCD, 0xE3, 0xCD, 0xAD, 0x9F, 0x1C, 0xE5, 0x8B,
            0x26, 0x75, 0x1F, 0x67, 0xA3, 0xCB, 0xB1, 0x40, 0xB1, 0x80, 0x8C, 0xF1, 0x87, 0xA4, 0xF4, 0xDF,
            0xC0, 0x4B, 0x05, 0x35, 0x7C, 0x5D, 0x1C, 0x0E, 0xEA, 0xC4, 0xC6, 0x6F, 0x9F, 0xF7, 0xF2, 0xE6,
        ];

        assert_eq!(cipher_cfb(&input, key, init_vector), expected);
    }
}