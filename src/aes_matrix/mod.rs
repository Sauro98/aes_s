use crate::math::{Math, INV_S_BOX, S_BOX};

mod aes_matrix_test;

#[derive(Debug)]
pub struct AesMatrix {}

/*
    Every bytes:[u8;16] array taken as argument in the functions of this module
    represents a bidimensional 4x4 array of bites structured like this:
    (the numbers are the position of the value in the array)

     0  4  8  12
     1  5  9  13
     2  6  10 14
     3  7  11 15

     So the array [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                   0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
    Would logically be interpreted the following matrix of bytes:

       col:   0     1    2    3
       row:
         0   0x00 0x44 0x88 0xCC
         1   0x11 0x55 0x99 0xDD
         2   0x22 0x66 0xAA 0xEE
         3   0x33 0x77 0xBB 0xFF


*/
impl AesMatrix {
    /**
     * Substitutes each byte of the matrix with the equivalent byte in
     * the secure box as described in the AES standard
     */
    pub fn substitute_bytes_8(bytes: &mut [u8; 16]) {
        for i in 0..16 {
            bytes[i] = S_BOX[bytes[i] as usize];
        }
    }

    /**
     * Substitutes each byte of the matrix with the equivalent byte in
     * the inverse secure box as described in the AES standard
     */
    pub fn inv_substitute_bytes_8(bytes: &mut [u8; 16]) {
        for i in 0..16 {
            bytes[i] = INV_S_BOX[bytes[i] as usize];
        }
    }

    /**
     * The shift rows transformation shifts each row to the left
     * by a number of positions equal to the index of the row,
     * so row 0 stays the same, row 1 goes 1 to the left (with carry)
     * and so on.
     */
    pub fn shift_rows_8(bytes: &mut [u8; 16]) {
        Self::shift_row_8(bytes, 1);
        Self::shift_row_8(bytes, 2);
        Self::shift_row_8(bytes, 3);
    }

    /**
     * Since the matrix is represented as an array of columns each
     * column starts at the next multiple of 4, so the first row is at the
     * multiples of 4, the second row at the multiples of 4 + 1 and so on
     */
    fn shift_row_8(bytes: &mut [u8; 16], index: usize) {
        for _ in 0..index {
            let temp = bytes[index];
            bytes[index] = bytes[0x4 + index];
            bytes[0x04 + index] = bytes[0x08 + index];
            bytes[0x08 + index] = bytes[0x0C + index];
            bytes[0x0C + index] = temp;
        }
    }

    /**
     * The shift rows transformation shifts each row to the right
     * by a number of positions equal to the index of the row,
     * so row 0 stays the same, row 1 goes 1 to the right (with carry)
     * and so on.
     */
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

    /**
     * Applies the inverse_mix_column transformation to eache column in the matrix.
     * Since the matrix is represented as an array of columns each column
     * starts at the next multiple of 4.
     */
    pub fn mix_columns_8(bytes: &mut [u8; 16]) {
        Self::mix_column_8(bytes, 0x00);
        Self::mix_column_8(bytes, 0x04);
        Self::mix_column_8(bytes, 0x08);
        Self::mix_column_8(bytes, 0x0C);
    }

    /**
     * Basically the inverse_mix_columns sets the bytes in each column to:
     *
     * col[0] = (col[0] * 0x02) xor (col[1] * 0x03) xor col[2] xor col[3]
     * col[1] = col[0] xor (col[1] * 0x02) xor (col[2] * 0x03) xor col[3]
     * col[2] = col[0] xor col[1] xor (col[2] * 0x02) xor (col[3] * 0x03)
     * col[3] = (col[0] * 0x03) xor col[1] xor col[2] xor (col[3] * 0x02)
     *
     * With '*' meaning the multiplication in the GF2 field as described by the AES standard
     */
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

    /**
     * Applies the inverse_mix_column transformation to eache column in the matrix.
     * Since the matrix is represented as an array of columns each column
     * starts at the next multiple of 4.
     */
    pub fn inv_mix_columns_8(bytes: &mut [u8; 16]) {
        Self::inv_mix_column_8(bytes, 0x00);
        Self::inv_mix_column_8(bytes, 0x04);
        Self::inv_mix_column_8(bytes, 0x08);
        Self::inv_mix_column_8(bytes, 0x0C);
    }

    /**
     * Basically the inverse_mix_columns sets the bytes in each column to:
     *
     * col[0] = (col[0] * 0x0e) xor (col[1] * 0x0b) xor (col[2] * 0x0d) xor (col[3] * 0x09)
     * col[1] = (col[0] * 0x09) xor (col[1] * 0x0e) xor (col[2] * 0x0b) xor (col[3] * 0x0d)
     * col[2] = (col[0] * 0x0d) xor (col[1] * 0x09) xor (col[2] * 0x0e) xor (col[3] * 0x0b)
     * col[3] = (col[0] * 0x0b) xor (col[1] * 0x0d) xor (col[2] * 0x09) xor (col[3] * 0x0e)
     *
     * With '*' meaning the multiplication in the GF2 field as described by the AES standard
     */
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

    /**
     * Adds a word of the key taken in input to each column in the matrix.
     * I would have loved to make key_words a &[u32;4] but unfortunately
     * I did not find a way to make a slice's size known at compile time.
     *
     * Since the matrix is expressed as a sequence of columns each column
     * starts at the next multiple of 4.
     */
    pub fn add_round_key_8(bytes: &mut [u8; 16], key_words: &[u32]) {
        for i in (0..16).step_by(4) {
            let key_bytes = key_words[i / 4].to_be_bytes();
            bytes[i] = bytes[i] ^ key_bytes[0];
            bytes[i + 1] = bytes[i + 1] ^ key_bytes[1];
            bytes[i + 2] = bytes[i + 2] ^ key_bytes[2];
            bytes[i + 3] = bytes[i + 3] ^ key_bytes[3];
        }
    }

    /**
     * Function used to expand the inverse key for the equivalent inverse cipher.
     * Since the key expansion works on arrays of 4 bytes words instead than on
     * array of bites I gave it its own function
     */
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
