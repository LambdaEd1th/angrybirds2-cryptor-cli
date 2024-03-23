use std::{
    error::Error,
    fs::File,
    io::{Read, Write},
};
mod crypto;
use crypto::Cryptor;

mod cli;
use cli::{Cli, CryptoModes};

use clap::Parser;

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

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    let mut input_file = File::open(cli.input_file)?;
    let mut input_index = File::open(cli.input_index)?;
    let mut input_file_buffer: Vec<u8> = Vec::new();
    input_file.read_to_end(&mut input_file_buffer)?;
    let mut input_index_buffer: Vec<u8> = Vec::new();
    input_index.read_to_end(&mut input_index_buffer)?;
    let output_buffer: Vec<u8>;

    let cryptor = Cryptor::new(&input_index_buffer, &input_file_buffer);
    match cli.crypto_mode {
        CryptoModes::Encrypt => {
            output_buffer = cryptor.encrypt()?;
        }
        CryptoModes::Decrypt => {
            output_buffer = cryptor.decrypt()?;
        }
    }
    let mut output_file = File::create(cli.output_file)?;
    output_file.write_all(&output_buffer)?;
    Ok(())
}
