use crate::cli::handle_args;
use std::process::exit;

mod cli;
mod encryption;
mod filesystem;
mod kdf;
mod styles;
mod utils;

fn main() {
    let _ = color_eyre::install();

    handle_args().unwrap_or_else(|e| {
        eprintln!("{}", e);
        exit(1);
    });
}
