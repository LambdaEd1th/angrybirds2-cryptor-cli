use std::path::PathBuf;

use clap::{Parser, ValueEnum};

#[derive(Parser, Clone, Debug, PartialEq, Eq)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// What crypto mode to run the program in
    #[arg(value_enum)]
    pub crypto_mode: CryptoModes,

    /// Input index
    #[arg(value_name = "INPUT_INDEX")]
    pub input_index: PathBuf,

    /// Input file
    #[arg(value_name = "INPUT_FILE")]
    pub input_file: PathBuf,

    /// Output file
    #[arg(value_name = "OUTPUT_FILE")]
    pub output_file: PathBuf,
}

#[derive(ValueEnum, Clone, Debug, PartialEq, Eq)]
pub enum CryptoModes {
    Encrypt,
    Decrypt,
}
