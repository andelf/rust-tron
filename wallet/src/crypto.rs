use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};
use sha2::{Digest, Sha512};
use std::{convert::TryInto, mem};

use crate::error::Error;

type Aes256CfbEnc = cfb_mode::Encryptor<aes::Aes256>;
type Aes256CfbDec = cfb_mode::Decryptor<aes::Aes256>;

// NOTE: key, sha512 key
pub fn aes_encrypt(key: &[u8], plain_text: &[u8]) -> Result<Vec<u8>, Error> {
    let iv: [u8; 16] = key[32..48].try_into().unwrap(); // BlockSize [u8; 16]
    let key: [u8; 32] = key[..32].try_into().unwrap(); //  KeySize [u8; 32]

    let mut buffer = plain_text.to_owned();

    // encrypt plaintext
    Aes256CfbEnc::new(&key.into(), &iv.into())
        .encrypt(&mut buffer);

    Ok(buffer)
}

pub fn aes_decrypt(key: &[u8], cipher_text: &[u8]) -> Result<Vec<u8>, Error> {
    let iv: [u8; 16] = key[32..48].try_into().unwrap(); // BlockSize [u8; 16]
    let key: [u8; 32] = key[..32].try_into().unwrap(); //  KeySize [u8; 32]

    let mut buffer = cipher_text.to_owned();

    Aes256CfbDec::new(&key.into(), &iv.into())
        .decrypt(&mut buffer);

    Ok(buffer)
}

#[inline]
pub fn sha512(input: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(input);
    // NOTE: From<GenericArray<u8, 64>> is not impl-ed for [u8; 64]
    unsafe { mem::transmute(hasher.finalize()) }
}
