use std::{
    error::Error,
    fs::File,
    io::{Read, Write},
};

use angrybirds2_cryptor_cli::{constant_items, crypto::Cryptor};

use clap::Parser;


// #[test]
// fn dec() -> Result<(), Box<dyn Error>> {
//     let mut input_file = File::open("/Users/edith/Desktop/index")?;
//     let mut input_buffer: Vec<u8> = Vec::new();
//     input_file.read_to_end(&mut input_buffer)?;
//     let cryptor: Cryptor = Cryptor::new(constant_items::XOR_KEY, &input_buffer);
//     let mut output_file = File::create("/Users/edith/Desktop/test.bin")?;
//     output_file.write_all(&cryptor.sha1(&input_buffer))?;
//     Ok(())
// }

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

#[test]
fn sha256_hash() -> Result<(), Box<dyn Error>> {
    const INDEX: &[u8] = &[
        0xAB, 0xBA, 0x01, 0x00, 0xE4, 0xA2, 0xED, 0xBE, 0x6C, 0x61, 0x6D, 0x62, 0x64, 0x61, 0x5F,
        0x65, 0x64, 0x31, 0x74, 0x68, 0x00, 0x00, 0x00, 0x00, 0x61, 0x6E, 0x67, 0x72, 0x79, 0x62,
        0x69, 0x72, 0x64, 0x73, 0x32, 0x2D, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6F, 0x72, 0x2D, 0x63,
        0x6C, 0x69, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let cryptor: Cryptor = Cryptor::new(constant_items::XOR_KEY, INDEX);
    let original_string = "CombinedPlayerData";
    let hash_result = &cryptor.sha256(original_string);
    let hash_string = "B4F59D3E9582F13D98B85102B4003E377A9434837B71846F44C05637D2613FA1";
    assert!(
        hash_result == hash_string,
        "original_string:{}\nhash_result:{}\nhash_string:{}",
        original_string,
        hash_result,
        hash_string
    );
    Ok(())
}

fn main() {}
