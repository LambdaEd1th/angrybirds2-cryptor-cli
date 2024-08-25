use std::borrow::Cow;

use rust_embed::Embed;

#[derive(Embed)]
#[folder = "./resources"]
pub struct Resource;

impl Resource {
    pub fn get_key() -> Cow<'static, [u8]> {
        match Self::get("xor_key.bin") {
            Some(file) => file.data,
            None => Cow::Borrowed(&[]),
        }
    }
}
