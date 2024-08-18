use std::{
    error::Error,
    fs::File,
    io::{Read, Write},
};
mod crypto;
use crypto::Cryptor;

mod cli;
use cli::{Cli, Commands};

mod resource;

use clap::Parser;

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt(args) => {
            let mut input_file = File::open(args.input_file)?;
            let mut input_index = File::open(args.input_index)?;
            let mut input_file_buffer: Vec<u8> = Vec::new();
            input_file.read_to_end(&mut input_file_buffer)?;
            let mut input_index_buffer: Vec<u8> = Vec::new();
            input_index.read_to_end(&mut input_index_buffer)?;
            let cryptor = Cryptor::new(&input_index_buffer, &input_file_buffer);

            let output_buffer = cryptor.encrypt()?;

            let mut output_file = File::create(args.output_file)?;
            output_file.write_all(&output_buffer)?;
        }
        Commands::Decrypt(args) => {
            let mut input_file = File::open(args.input_file)?;
            let mut input_index = File::open(args.input_index)?;
            let mut input_file_buffer: Vec<u8> = Vec::new();
            input_file.read_to_end(&mut input_file_buffer)?;
            let mut input_index_buffer: Vec<u8> = Vec::new();
            input_index.read_to_end(&mut input_index_buffer)?;
            let cryptor = Cryptor::new(&input_index_buffer, &input_file_buffer);

            let output_buffer = cryptor.decrypt()?;

            let mut output_file = File::create(args.output_file)?;
            output_file.write_all(&output_buffer)?;
        }
        Commands::List => {
            let sha256_map = Cryptor::sha256_map()?;
            for (file_name, sha256_string) in sha256_map {
                println!("{file_name:<27} - {sha256_string}");
            }
        }
    }
    Ok(())
}
