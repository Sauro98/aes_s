# AES_S

### Description

This is a library that offers AES encryption and decryption functionalities.

All the informations about the AES standard as well as all the data used in the tests was 
taken from [this paper](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)

### Usage

To crypt a block of 4x4 bytes: 

``` rust

external crate aes_s;

use aes_s::Cipher;
fn main() {
    let key_128 = [0x00112233, 0x44556677, 0x8899AABB, 0xCCDDEEFF];
    let cipher = Cipher::new_128(&key_128);
    let mut buffer = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
    cipher.cipher(&mut buffer);
    //here buffer hods the crypted content
}

```



## Contribution

This project is meant as an exercise to learn rust.     
Any tips regarding best practices and semantics are very welcome.      
Any help in improving performance or resources to study to achieve that goal are also very much appreciated.
