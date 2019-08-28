# AES_S

### Description

This is a library that offers AES encryption and decryption functionalities.

### Usage

To read a file, crypt it with a key and put the content in a vector: 

``` rust

external crate aes_s;

use aes_s::Cipher;
use std::io;
use std::io::prelude::*;
use std::fs::File;

fn main() {
    let key_128 = [0x00112233, 0x44556677, 0x8899AABB, 0xCCDDEEFF];
    let cipher = Cipher::new_128(&key_128);

    let mut f = File::open("foo.txt").unwrap();
    let mut buffer = [0; 16];
    let mut result = Vec::new();

    let mut count = f.read(&mut buffer).unwrap();
    while count != 0 {
        cipher.cipher(&mut buffer);
        result.extend_from_slice(&buffer);
        buffer = [0; 16]; // pad with zeroes if  (file length % 16) != 0
        count = f.read(&mut buffer).unwrap();
    }

    //here result holds the crypted content


}

```