use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fmt::{self, Display, Write},
};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256Enc>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256Dec>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cryptor<'cryptor> {
    pub xor_key: &'cryptor [u8],
    pub index: &'cryptor [u8],
}

impl<'cryptor> Cryptor<'cryptor> {
    const HEADER: &[u8] = &[0xAB, 0xBA, 0x01, 0x00];

    pub fn new(xor_key: &'cryptor [u8], index: &'cryptor [u8]) -> Self {
        Self { xor_key, index }
    }

    pub fn encrypt(&self, buffer: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let (key, iv) = self.xor_crypto()?;
        let encryptor = Aes256CbcEnc::new(&key.into(), &iv.into());
        let cipher_buffer = encryptor.encrypt_padded_vec_mut::<Pkcs7>(buffer);
        Ok(cipher_buffer)
    }

    pub fn decrypt(&self, buffer: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let (key, iv) = self.xor_crypto()?;
        let decryptor = Aes256CbcDec::new(&key.into(), &iv.into());
        let plain_buffer = decryptor.decrypt_padded_vec_mut::<Pkcs7>(buffer)?;
        Ok(plain_buffer)
    }

    fn xor_crypto(&self) -> Result<([u8; 32], [u8; 16]), Box<dyn Error>> {
        if &self.index[..4] != Self::HEADER {
            todo!()
        }

        let mut buffer: Vec<u8> = self.index[4..].to_vec();

        for i in 0..buffer.len() {
            buffer[i] ^= self.xor_key[i % self.xor_key.len()];
        }
        let iv_len = u16::from_le_bytes(buffer[0..2].try_into()?) as usize;
        let key_len = u16::from_le_bytes(buffer[2..4].try_into()?) as usize;
        let iv = &buffer[4..4 + iv_len];
        let key = &buffer[4 + iv_len..4 + iv_len + key_len];
        Ok((key.try_into()?, iv.try_into()?))
    }

    pub fn sha256(&self, string: &str) -> String {
        let mut string_buffer = self.xor_key.to_vec();
        for ch in string.to_string().chars() {
            for byte in ch.to_string().as_bytes().iter() {
                string_buffer.push(*byte);
            }
            string_buffer.push(0u8);
        }
        let result: Vec<u8> = Sha256::new_with_prefix(string_buffer).finalize().to_vec();
        let mut result_string = String::new();
        for element in result.iter() {
            write!(&mut result_string, "{:02X}", element).unwrap();
        }
        result_string
    }
}
