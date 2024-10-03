use aes::cipher::{
    block_padding::{Pkcs7, UnpadError},
    BlockDecryptMut, BlockEncryptMut, KeyIvInit,
};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fmt::Write};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256Enc>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256Dec>;

pub type Result<T> = core::result::Result<T, Error>;

const HEADER: &[u8] = &[0xAB, 0xBA, 0x01, 0x00];

const XOR_KEY: &[u8] = &[
    0xF4, 0xA2, 0xCD, 0xBE, 0x75, 0xC7, 0x15, 0x20, 0xAE, 0xFB, 0x9D, 0x6B, 0x6A, 0x26, 0x7C, 0xDA,
    0xCD, 0x20, 0x90, 0x36, 0xDA, 0x38, 0x61, 0x41, 0x15, 0x51, 0xD5, 0xD4, 0xE4, 0x37, 0xAD, 0xD0,
    0x2F, 0x35, 0x80, 0xC3, 0x12, 0xA1, 0x48, 0x99, 0x68, 0x5A, 0x87, 0xF3, 0xBD, 0x20, 0x63, 0xE7,
    0x13, 0xBF, 0xA5, 0xF0, 0x6C, 0xB8, 0x63, 0xA5, 0xB0, 0x2E, 0x19, 0xB6, 0x54, 0x36, 0x0B, 0x5A,
    0xE6, 0x16, 0xD9, 0x96, 0x35, 0x2E, 0x8D, 0x14, 0x58, 0x05, 0x2E, 0x48, 0xF2, 0x67, 0x44, 0xDA,
    0xD4, 0x3D, 0x9C, 0xE5, 0x76, 0x64, 0xBC, 0x4B, 0xFE, 0x20, 0x5C, 0xA3, 0x1C, 0xEF, 0x73, 0xD3,
    0x41, 0x57, 0xC4, 0xF2, 0xFB, 0x4C, 0x95, 0x4C, 0x90, 0xEA, 0xC1, 0xE1, 0x6C, 0xB3, 0x0F, 0x78,
    0x42, 0x75, 0xAE, 0x4A, 0xD6, 0xA7, 0x88, 0xD9, 0x71, 0x28, 0x99, 0x55, 0x3D, 0x92, 0x23, 0x25,
    0xE3, 0x65, 0xD5, 0x7C, 0xD2, 0x9E, 0xFF, 0xB7, 0x58, 0x69, 0xE0, 0x24, 0x90, 0x1C, 0x31, 0xEB,
    0x60, 0x56, 0x41, 0xE3, 0x98, 0x48, 0x68, 0x79, 0xF8, 0xCF, 0x05, 0xEC, 0x24, 0x50, 0xFA, 0xF3,
    0xC5, 0x54, 0x58, 0x30, 0xD9, 0x10, 0x75, 0x9A, 0x55, 0x22, 0x75, 0x38, 0xDE, 0x5E, 0x33, 0xCA,
    0xF4, 0x63, 0x19, 0xD4, 0x24, 0x70, 0xF3, 0x3F, 0xB7, 0x89, 0x06, 0x36, 0xF8, 0x15, 0xB3, 0xD7,
    0x61, 0xC0, 0xE5, 0x42, 0x58, 0xF2, 0xD0, 0xB6, 0xF8, 0x64, 0x7B, 0x84, 0x16, 0xE9, 0xA1, 0x42,
    0x15, 0x4C, 0xAA, 0xBA, 0x2B, 0x95, 0x10, 0x98, 0x8F, 0x11, 0xE2, 0x2E, 0x35, 0x5B, 0x5D, 0x92,
    0x4E, 0x45, 0x39, 0xFD, 0x25, 0xF8, 0x99, 0x98, 0x8D, 0x55, 0x67, 0xB7, 0xEE, 0xB2, 0xE2, 0x37,
    0xF6, 0x13, 0x39, 0x67, 0xAA, 0x02, 0x7A, 0x8E, 0x76, 0x11, 0xFF, 0xD7, 0xC8, 0x7F, 0xFE, 0x7A,
];

// 8DA4F614BD109FD64248704E48E720719DBA53061539CB4C46B6ECBA475C6E5C - Session_ID
// D8BEB2B529C8FAC1BC697121125618BF790BD7F87AE759266CA6CC9CC07B6035 - FriendsCache
// 5CC8D4E0834E058B4A47D33C3B97BB1505D33A626B4C5A74699DE886B7BF871F - PVPPlayerData
// 91C8ECDC2923E2A7E9EC4817C7D6D5FBF25E05BFB2402B3714ABFCD5A3C001BF - FbFriendsCache
// B2BD44808B01FEEE6C1B8917B851CEF64978B5560EA10368424F7EE9196DF6BA - BeaconAppConfig
// B530BFB9C225DF26B7D4DFE3E5808F16FB5ACFF9DC3481BA677EC62C85E3BF62 - AbbaFriendsCache
// A9A96744AB58AFA572B442A99668F25E57622CF995B250737CDED7C6F6480FFA - PublicPlayerData
// B4F59D3E9582F13D98B85102B4003E377A9434837B71846F44C05637D2613FA1 - CombinedPlayerData
// 937A9CA7A99C29ADB867F6B0000DD6310FC7D9DEF559FC2436D0F0E64F0B3E3D - TowerOfFortuneState
// E817BFFB14A03700401432D98906062C116497657A48885E9DBC5F1989CE3AE5 - HockeyIOSCurrentAppInfo
// A664CA94E883A423A522AE9778BDB3B1379BD7FC72E90CCA361B1396E3BEC2E1 - LastTimeBundleWasRefreshed
// E266F162807E3EB7692756371F9BD111A2D4FF29E26DBE9C982160A93E9FBB11 - HockeyAndroidCurrentAppInfo

const FILE_NAMES: &[&str] = &[
    "Session_ID",
    "FriendsCache",
    "PVPPlayerData",
    "FbFriendsCache",
    "BeaconAppConfig",
    "AbbaFriendsCache",
    "PublicPlayerData",
    "CombinedPlayerData",
    "TowerOfFortuneState",
    "HockeyIOSCurrentAppInfo",
    "LastTimeBundleWasRefreshed",
    "HockeyAndroidCurrentAppInfo",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cryptor<'cryptor> {
    pub index: &'cryptor [u8],
    pub input_file: &'cryptor [u8],
}

impl<'cryptor> Cryptor<'cryptor> {
    pub fn new(index: &'cryptor [u8], input_file: &'cryptor [u8]) -> Self {
        Self { index, input_file }
    }

    pub fn encrypt(&self) -> Result<Vec<u8>> {
        let (key, iv) = self.read_index()?;
        let encryptor = Aes256CbcEnc::new(&key.into(), &iv.into());
        let cipher_buffer = encryptor.encrypt_padded_vec_mut::<Pkcs7>(self.input_file);
        Ok(cipher_buffer)
    }

    pub fn decrypt(&self) -> Result<Vec<u8>> {
        let (key, iv) = self.read_index()?;
        let decryptor = Aes256CbcDec::new(&key.into(), &iv.into());
        let plain_buffer = decryptor.decrypt_padded_vec_mut::<Pkcs7>(self.input_file)?;
        Ok(plain_buffer)
    }

    pub fn sha256_map() -> Result<BTreeMap<String, String>> {
        let mut sha256_map: BTreeMap<String, String> = BTreeMap::new();
        for &name in FILE_NAMES {
            sha256_map.insert(name.to_string(), Self::sha256_string(name)?);
        }
        Ok(sha256_map)
    }

    fn read_index(&self) -> Result<([u8; 32], [u8; 16])> {
        let mut file_header = [0u8; 4];
        file_header.clone_from_slice(&self.index[..4]);
        let mut buffer: Vec<u8> = match &file_header == HEADER {
            true => self.index[4..].to_vec(),
            false => {
                return Err(Error::HeaderError(file_header));
            }
        };

        for i in 0..buffer.len() {
            buffer[i] ^= XOR_KEY[i % XOR_KEY.len()];
        }
        let (mut iv_buffer, mut key_buffer) = (
            [0; std::mem::size_of::<u16>()],
            [0; std::mem::size_of::<u16>()],
        );
        iv_buffer.clone_from_slice(&buffer[0..2]);
        key_buffer.clone_from_slice(&buffer[2..4]);
        let iv_len = u16::from_le_bytes(iv_buffer) as usize;
        let key_len = u16::from_le_bytes(key_buffer) as usize;
        let (mut iv, mut key) = ([0u8; 16], [0u8; 32]);
        iv.clone_from_slice(&buffer[4..4 + iv_len]);
        key.clone_from_slice(&buffer[4 + iv_len..4 + iv_len + key_len]);
        Ok((key, iv))
    }

    pub fn sha256_string(string: &str) -> Result<String> {
        let mut string_buffer = XOR_KEY.to_vec();
        for ch in string.to_string().chars() {
            for byte in ch.to_string().as_bytes().iter() {
                string_buffer.push(*byte);
            }
            string_buffer.push(0u8);
        }
        let result: Vec<u8> = Sha256::new_with_prefix(string_buffer).finalize().to_vec();
        let mut result_string = String::new();
        for element in result.iter() {
            write!(&mut result_string, "{element:02X}")?;
        }
        Ok(result_string)
    }
}

#[derive(Debug)]
pub enum Error {
    HeaderError([u8; 4]),
    AesCryptoError(UnpadError),
    FormatError(core::fmt::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            Self::AesCryptoError(err) => write!(f, "AesCryptoError: {err}"),
            Self::HeaderError(arr) => write!(f, "HeaderError: {arr:#X?}"),
            Self::FormatError(err) => write!(f, "Sha256error: {err}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self {
            Self::HeaderError(_) => None,
            Self::AesCryptoError(err) => Some(err),
            Self::FormatError(err) => Some(err),
        }
    }
}

impl From<UnpadError> for Error {
    fn from(err: UnpadError) -> Self {
        Self::AesCryptoError(err)
    }
}

impl From<core::fmt::Error> for Error {
    fn from(err: core::fmt::Error) -> Self {
        Self::FormatError(err)
    }
}
