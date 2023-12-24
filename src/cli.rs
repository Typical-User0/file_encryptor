use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use crate::encryption::{
    gen_hash_salt_from_kdf, get_aes_128gcm_key, get_aes_256gcm_key, get_chacha20poly1305_key,
    AEADAlgorithm, CipherMetadata, KeyNoncePair,
};
use crate::filesystem::{decrypt_file, FileEncryptor};
use crate::kdf::KDFMetadata;
use clap::{Args, Parser, Subcommand};

/// File encryption/decryption tool
#[derive(Debug, Parser)]
#[command(name = "crypt", styles=crate::styles::get_styles())]
#[command(about = "Educational Purposes only file encryption/decryption tool", long_about = None)]
pub struct CLI {
    #[command(subcommand)]
    pub commands: SubCommands,
}

#[derive(Debug, Subcommand)]
pub enum SubCommands {
    /// Encrypt files
    #[command(arg_required_else_help = true)]
    Encrypt {
        algorithm: AEADAlgorithm,
        /// file to encrypt
        file: PathBuf,
        output: PathBuf,
    },
    /// Decrypt files
    #[command(arg_required_else_help = true)]
    Decrypt {
        /// file to decrypt
        file: PathBuf,
        output: PathBuf,
    },
}

fn check_filename(file: &PathBuf, output_file: &PathBuf) {
    if !file.exists() {
        panic!(
            "Path `{}` doesn't exist!",
            file.to_str().expect("Invalid path")
        );
    }

    if output_file.exists() {
        print!(
            "Path `{}` already exists. Do you want to overwrite it? (Y/n): ",
            output_file.to_str().expect("Invalid path")
        );
        std::io::stdout().flush().expect("failed to flush terminal");

        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .expect("Failed to read answer");
        if answer.trim().to_ascii_lowercase() != "y" {
            println!("here");
            std::process::exit(0);
        }
    }

    for file in [file, output_file] {
        if file.is_dir() {
            panic!("`{}` is not a file", file.to_str().expect("Invalid path"))
        }
    }

    if file == output_file {
        panic!("Input and output files can't be the same")
    }
}

fn get_password() -> String {
    let password = rpassword::prompt_password("Enter password: ").unwrap();
    return password;
}

pub fn handle_args() -> Result<(), Box<dyn Error>> {
    let args = CLI::parse();
    match args.commands {
        SubCommands::Decrypt { file, output } => {
            // check if filenames to encrypt/decrypt do exist
            check_filename(&file, &output);

            let passphrase = get_password();

            handle_decryption(passphrase.as_bytes(), file, output)?;
        }
        SubCommands::Encrypt {
            file,
            output,
            algorithm,
        } => {
            // check if filenames to encrypt/decrypt do exist
            check_filename(&file, &output);

            let passphrase = get_password();

            handle_encryption(passphrase.as_bytes(), algorithm, file, output)?;
        }
    }

    Ok(())
}

fn handle_encryption(
    passphrase: &[u8],
    algorithm: AEADAlgorithm,
    file: PathBuf,
    output_file: PathBuf,
) -> Result<(), Box<dyn Error>> {
    let hash_salt_pair = gen_hash_salt_from_kdf(algorithm, None, passphrase)?;

    let kdf_metadata = KDFMetadata::new(hash_salt_pair.salt().clone());

    let res = match algorithm {
        AEADAlgorithm::CHACHA20Poly1305 => {
            let key_nonce_pair = get_chacha20poly1305_key(hash_salt_pair.hash_bytes(), None)?;

            let cipher_metadata =
                CipherMetadata::<ChaCha20Poly1305>::new(algorithm, key_nonce_pair.nonce().clone());

            key_nonce_pair
                .key()
                .encrypt_file(file, output_file, &kdf_metadata, &cipher_metadata)
                .expect("Failed to encrypt file")
        }
        AEADAlgorithm::Aes256GCM => {
            let key_nonce_pair = get_aes_256gcm_key(hash_salt_pair.hash_bytes(), None)?;

            let cipher_metadata =
                CipherMetadata::<Aes256Gcm>::new(algorithm, key_nonce_pair.nonce().clone());

            key_nonce_pair
                .key()
                .encrypt_file(file, output_file, &kdf_metadata, &cipher_metadata)
                .expect("Failed to encrypt file");
        }
        AEADAlgorithm::Aes128GCM => {
            let key_nonce_pair = get_aes_128gcm_key(hash_salt_pair.hash_bytes(), None)?;

            let cipher_metadata =
                CipherMetadata::<Aes128Gcm>::new(algorithm, key_nonce_pair.nonce().clone());

            key_nonce_pair
                .key()
                .encrypt_file(file, output_file, &kdf_metadata, &cipher_metadata)
                .expect("Failed to encrypt file");
        }
    };
    Ok(())
}

fn handle_decryption(
    passphrase: &[u8],
    file: PathBuf,
    output_file: PathBuf,
) -> Result<(), Box<dyn Error>> {
    let plaintext = decrypt_file(file, passphrase)?;

    let mut file = File::create(output_file)?;

    file.write_all(&plaintext)?;
    Ok(())
}
