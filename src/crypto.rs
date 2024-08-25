use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use sha2::{Digest, Sha256};
use std::{borrow::Cow, collections::BTreeMap, fmt::Write, sync::LazyLock};

use crate::resource::Resource;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256Enc>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256Dec>;

const HEADER: &[u8] = &[0xAB, 0xBA, 0x01, 0x00];

static XOR_KEY: LazyLock<Cow<'static, [u8]>> = LazyLock::new(|| Resource::get_key());

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

    pub fn encrypt(&self) -> Result<Vec<u8>, CryptorError> {
        let (key, iv) = self.read_index()?;
        let encryptor = Aes256CbcEnc::new(&key.into(), &iv.into());
        let cipher_buffer = encryptor.encrypt_padded_vec_mut::<Pkcs7>(self.input_file);
        Ok(cipher_buffer)
    }

    pub fn decrypt(&self) -> Result<Vec<u8>, CryptorError> {
        let (key, iv) = self.read_index()?;
        let decryptor = Aes256CbcDec::new(&key.into(), &iv.into());
        let plain_buffer = decryptor
            .decrypt_padded_vec_mut::<Pkcs7>(self.input_file)
            .map_err(|e| CryptorError::AesCryptoError(e.to_string()))?;
        Ok(plain_buffer)
    }

    pub fn sha256_map() -> Result<BTreeMap<String, String>, CryptorError> {
        let mut sha256_map: BTreeMap<String, String> = BTreeMap::new();
        for &name in FILE_NAMES {
            sha256_map.insert(name.to_string(), Self::sha256_string(name)?);
        }
        Ok(sha256_map)
    }

    fn read_index(&self) -> Result<([u8; 32], [u8; 16]), CryptorError> {
        let mut buffer: Vec<u8> = match &self.index[..4] == HEADER {
            true => self.index[4..].to_vec(),
            false => {
                return Err(CryptorError::HeaderError("Invalid header".to_string()));
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

    pub fn sha256_string(string: &str) -> Result<String, CryptorError> {
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
            write!(&mut result_string, "{element:02X}")
                .map_err(|e| CryptorError::Sha256Error(e.to_string()))?;
        }
        Ok(result_string)
    }
}

#[derive(Debug)]
pub enum CryptorError {
    HeaderError(String),
    AesCryptoError(String),
    Sha256Error(String),
}

impl std::fmt::Display for CryptorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AesCryptoError(s) => write!(f, "AesCryptoError: {}", s),
            Self::HeaderError(s) => write!(f, "AesCryptoError: {}", s),
            Self::Sha256Error(s) => write!(f, "Sha256error: {}", s),
        }
    }
}

impl std::error::Error for CryptorError {}
