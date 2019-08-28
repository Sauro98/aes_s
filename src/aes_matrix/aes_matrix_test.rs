#[cfg(test)]

mod aes_matrix_test {
    use crate::aes_matrix::AesMatrix;
    use crate::math::Math;
    #[test]
    fn it_substitutes_bytes() {
        let mut content: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        AesMatrix::substitute_bytes_8(&mut content);
        assert_eq!(
            content,
            [
                0x63, 0x7C, 0x77, 0x7B, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7,
                0xab, 0x76
            ]
        );
        let mut content: [u8; 16] = [
            0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed,
            0xfe, 0x0f,
        ];
        AesMatrix::substitute_bytes_8(&mut content);
        assert_eq!(
            content,
            [
                0xca, 0xfd, 0x23, 0x1a, 0x20, 0x4d, 0x38, 0x17, 0x46, 0xd3, 0xf4, 0x1f, 0x86, 0x55,
                0xbb, 0x76
            ]
        );
    }

    #[test]
    fn it_shifts_rows() {
        let mut content = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        AesMatrix::shift_rows_8(&mut content);
        assert_eq!(
            content,
            [
                0x00, 0x05, 0x0a, 0x0f, 0x04, 0x09, 0x0e, 0x03, 0x08, 0x0d, 0x02, 0x07, 0x0c, 0x01,
                0x06, 0x0b
            ]
        );
    }

    #[test]
    fn it_mixes_columns() {
        let mut content: [u8; 16] = [
            0x63, 0x53, 0xe0, 0x8c, 0x09, 0x60, 0xe1, 0x04, 0xcd, 0x70, 0xb7, 0x51, 0xba, 0xca,
            0xd0, 0xe7,
        ];
        AesMatrix::mix_columns_8(&mut content);
        assert_eq!(
            content,
            [
                0x5f, 0x72, 0x64, 0x15, 0x57, 0xf5, 0xbc, 0x92, 0xf7, 0xbe, 0x3b, 0x29, 0x1d, 0xb9,
                0xf9, 0x1a
            ]
        );
    }

    #[test]
    fn it_adds_round_key() {
        let mut content: [u8; 16] = [
            0x5f, 0x72, 0x64, 0x15, 0x57, 0xf5, 0xbc, 0x92, 0xf7, 0xbe, 0x3b, 0x29, 0x1d, 0xb9,
            0xf9, 0x1a,
        ];
        AesMatrix::add_round_key_8(
            &mut content,
            &[0xd6aa74fd, 0xd2af72fa, 0xdaa678f1, 0xd6ab76fe],
        );
        assert_eq!(
            content,
            [
                0x89, 0xd8, 0x10, 0xe8, 0x85, 0x5a, 0xce, 0x68, 0x2d, 0x18, 0x43, 0xd8, 0xcb, 0x12,
                0x8f, 0xe4
            ]
        );
    }

    #[test]
    fn it_does_a_full_round() {
        let mut content: [u8; 16] = [
            0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0,
            0xe0, 0xf0,
        ];
        AesMatrix::substitute_bytes_8(&mut content);
        AesMatrix::shift_rows_8(&mut content);
        AesMatrix::mix_columns_8(&mut content);
        AesMatrix::add_round_key_8(
            &mut content,
            &[0xd6aa74fd, 0xd2af72fa, 0xdaa678f1, 0xd6ab76fe],
        );
        assert_eq!(
            content,
            [
                0x89, 0xd8, 0x10, 0xe8, 0x85, 0x5a, 0xce, 0x68, 0x2d, 0x18, 0x43, 0xd8, 0xcb, 0x12,
                0x8f, 0xe4
            ]
        );
    }

    #[test]
    fn it_does_inv_shift_row() {
        let mut content = [
            0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0,
            0xe0, 0xf0,
        ];
        AesMatrix::shift_rows_8(&mut content);
        AesMatrix::inv_shift_rows_8(&mut content);
        assert_eq!(
            content,
            [
                0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0,
                0xe0, 0xf0
            ]
        );
    }

    #[test]
    fn it_does_inv_mix_columns() {
        let mut content = [
            0xbd, 0x6e, 0x7c, 0x3d, 0xf2, 0xb5, 0x77, 0x9e, 0x0b, 0x61, 0x21, 0x6e, 0x8b, 0x10,
            0xb6, 0x89,
        ];
        AesMatrix::inv_mix_columns_8(&mut content);
        assert_eq!(
            content,
            [
                0x47, 0x73, 0xb9, 0x1f, 0xf7, 0x2f, 0x35, 0x43, 0x61, 0xcb, 0x01, 0x8e, 0xa1, 0xe6,
                0xcf, 0x2c
            ]
        );
    }
}