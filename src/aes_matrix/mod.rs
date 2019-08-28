use crate::math::{Math, INV_S_BOX, S_BOX};

mod aes_matrix_test;

#[derive(Debug)]
pub struct AesMatrix {}

impl AesMatrix {
    pub fn substitute_bytes_8(bytes: &mut [u8; 16]) {
        for i in 0..16 {
            bytes[i] = S_BOX[bytes[i] as usize];
        }
    }

    pub fn inv_substitute_bytes_8(bytes: &mut [u8; 16]) {
        for i in 0..16 {
            bytes[i] = INV_S_BOX[bytes[i] as usize];
        }
    }

    pub fn shift_rows_8(bytes: &mut [u8; 16]) {
        Self::shift_row_8(bytes, 1);
        Self::shift_row_8(bytes, 2);
        Self::shift_row_8(bytes, 3);
    }

    fn shift_row_8(bytes: &mut [u8; 16], index: usize) {
        for _ in 0..index {
            let temp = bytes[0 + index];
            bytes[0 + index] = bytes[4 + index];
            bytes[4 + index] = bytes[8 + index];
            bytes[8 + index] = bytes[12 + index];
            bytes[12 + index] = temp;
        }
    }

    pub fn inv_shift_rows_8(bytes: &mut [u8; 16]) {
        Self::inv_shift_row_8(bytes, 1);
        Self::inv_shift_row_8(bytes, 2);
        Self::inv_shift_row_8(bytes, 3);
    }

    fn inv_shift_row_8(bytes: &mut [u8; 16], index: usize) {
        for _ in 0..index {
            let temp = bytes[12 + index];
            bytes[12 + index] = bytes[8 + index];
            bytes[8 + index] = bytes[4 + index];
            bytes[4 + index] = bytes[index];
            bytes[index] = temp;
        }
    }

    pub fn mix_columns_8(bytes: &mut [u8; 16]) {
        Self::mix_column_8(bytes, 0x00);
        Self::mix_column_8(bytes, 0x04);
        Self::mix_column_8(bytes, 0x08);
        Self::mix_column_8(bytes, 0x0C);
    }

    fn mix_column_8(bytes: &mut [u8; 16], offset: usize) {
        let mut column_bytes = [
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ];
        for index in 0..4 {
            bytes[offset + index] = Math::x_time(column_bytes[0])
                ^ Math::multiplication_by_03(column_bytes[1])
                ^ column_bytes[2]
                ^ column_bytes[3];
            let temp = column_bytes[0];
            column_bytes[0] = column_bytes[1];
            column_bytes[1] = column_bytes[2];
            column_bytes[2] = column_bytes[3];
            column_bytes[3] = temp;
        }
    }

    pub fn inv_mix_columns_8(bytes: &mut [u8; 16]) {
        Self::inv_mix_column_8(bytes, 0x00);
        Self::inv_mix_column_8(bytes, 0x04);
        Self::inv_mix_column_8(bytes, 0x08);
        Self::inv_mix_column_8(bytes, 0x0C);
    }

    fn inv_mix_column_8(bytes: &mut [u8; 16], offset: usize) {
        let mut column_bytes = [
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ];
        for index in 0..4 {
            bytes[offset + index] = Math::multiplication_by_0e(column_bytes[0])
                ^ Math::multiplication_by_0b(column_bytes[1])
                ^ Math::multiplication_by_0d(column_bytes[2])
                ^ Math::multiplication_by_09(column_bytes[3]);
            let temp = column_bytes[0];
            column_bytes[0] = column_bytes[1];
            column_bytes[1] = column_bytes[2];
            column_bytes[2] = column_bytes[3];
            column_bytes[3] = temp;
        }
    }

    pub fn add_round_key_8(bytes: &mut [u8; 16], key_words: &[u32]) {
        for i in 0..4 {
            let key_bytes = key_words[i].to_be_bytes();
            bytes[i * 4] = bytes[i * 4] ^ key_bytes[0];
            bytes[(i * 4) + 1] = bytes[(i * 4) + 1] ^ key_bytes[1];
            bytes[(i * 4) + 2] = bytes[(i * 4) + 2] ^ key_bytes[2];
            bytes[(i * 4) + 3] = bytes[(i * 4) + 3] ^ key_bytes[3];
        }
    }

     pub fn inv_mix_column_a(columns: &mut [u32; 4], index: usize) {
        let mut column_bytes: [u8; 4] = [
            ((columns[index] & 0xff000000) >> 24) as u8,
            ((columns[index] & 0x00ff0000) >> 16) as u8,
            ((columns[index] & 0x0000ff00) >> 8) as u8,
            (columns[index] & 0x000000ff) as u8,
        ];
        let mut new_column: u32 = 0;
        for index in 0..4 {
            let curr_byte = Math::multiplication_by_0e(column_bytes[0])
                ^ Math::multiplication_by_0b(column_bytes[1])
                ^ Math::multiplication_by_0d(column_bytes[2])
                ^ Math::multiplication_by_09(column_bytes[3]);
            let temp = column_bytes[0];
            column_bytes[0] = column_bytes[1];
            column_bytes[1] = column_bytes[2];
            column_bytes[2] = column_bytes[3];
            column_bytes[3] = temp;
            new_column = new_column | ((curr_byte as u32) << ((3 - index) * 8));
        }
        columns[index] = new_column;
    }
}
