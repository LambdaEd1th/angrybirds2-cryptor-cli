use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

const HELP_TEMPLATE: &str = "{before-help}{about} by @{author-with-newline}\n{usage-heading} {usage}\n\n{all-args}{after-help}";

#[derive(Parser, Clone, Debug, PartialEq, Eq)]
#[command(author, version, about, long_about = None)]
#[command(next_line_help = true)]
#[command(help_template = HELP_TEMPLATE)]
pub struct Cli {
    /// What mode to run the program in
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Clone, Debug, PartialEq, Eq)]
pub enum Commands {
    /// Encrypt mode
    Encrypt(CryptoArgs),

    /// Decrypt mode
    Decrypt(CryptoArgs),

    /// List the original file name
    List,
}

#[derive(Args, Clone, Debug, PartialEq, Eq)]
pub struct CryptoArgs {
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
