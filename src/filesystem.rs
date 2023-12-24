use crate::encryption::{
    gen_hash_salt_from_kdf, get_aes_128gcm_key, get_aes_256gcm_key, get_chacha20poly1305_key,
    AEADAlgorithm, CipherMetadata,
};
use crate::kdf::KDFMetadata;
use aes_gcm::aead::{Aead, Nonce};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use argon2::password_hash::SaltString;
use base64::{engine::general_purpose, Engine as _};
use byteorder::{ReadBytesExt, WriteBytesExt};
use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::{AeadCore, AeadInPlace};
use std::error::Error;
use std::io::{ErrorKind, Write};
use std::path::PathBuf;
use std::{
    fs::File,
    io::{self, Read},
};

impl KDFMetadata {
    fn from_reader(mut rdr: impl Read) -> io::Result<Self> {
        // 16-byte salt
        let mut metadata_buf: [u8; 16] = [0; 16];

        rdr.read_exact(&mut metadata_buf)?;

        let base_64_string = general_purpose::STANDARD_NO_PAD.encode(&metadata_buf);
        let salt_string = SaltString::from_b64(&base_64_string)
            .map_err(|e| io::Error::new(ErrorKind::InvalidInput, "Invalid salt string"))?;

        Ok(KDFMetadata::new(salt_string))
    }

    fn write(&self, mut writer: impl Write) -> io::Result<()> {
        let base64_bytes = self.salt().to_string();

        let raw_bytes = general_purpose::STANDARD_NO_PAD
            .decode(&base64_bytes)
            .map_err(|e| io::Error::new(ErrorKind::InvalidInput, e.to_string()))?;

        writer.write_all(raw_bytes.as_slice())?;
        Ok(())
    }
}

impl<T: aes_gcm::AeadCore> CipherMetadata<T> {
    fn from_reader(mut rdr: impl Read) -> io::Result<Self> {
        let algorithm: AEADAlgorithm = rdr
            .read_u8()?
            .try_into()
            .map_err(|e| io::Error::new(ErrorKind::InvalidInput, "Invalid byte"))?;
        let nonce = {
            let mut buf: [u8; 12] = [0; 12];
            rdr.read_exact(&mut buf)?;
            Nonce::<T>::from_slice(&buf).clone()
        };

        let metadata = CipherMetadata::new(algorithm, nonce);
        Ok(metadata)
    }

    fn write(&self, mut writer: impl Write) -> io::Result<()> {
        writer.write_u8(self.algorithm() as u8)?;
        writer.write_all(self.nonce())?;

        Ok(())
    }
}

fn write_kdf_metadata(file: &mut File, kdf_metadata: &KDFMetadata) -> io::Result<()> {
    kdf_metadata.write(file)?;
    Ok(())
}

pub fn read_kdf_metadata(file: &File, algorithm: AEADAlgorithm) -> io::Result<KDFMetadata> {
    Ok(KDFMetadata::from_reader(file)?)
}

fn write_cipher_metadata<T: aes_gcm::AeadCore>(
    file: &mut File,
    cipher_metadata: &CipherMetadata<T>,
) -> io::Result<()> {
    cipher_metadata.write(file)?;
    Ok(())
}

pub fn read_cipher_metadata(file: &File) -> io::Result<CipherMetadata<impl AeadCore>> {
    Ok(CipherMetadata::<Aes256Gcm>::from_reader(file)?)
}

fn write_metadata<T: aes_gcm::AeadCore>(
    file: &mut File,
    cipher_metadata: &CipherMetadata<T>,
    kdf_metadata: &KDFMetadata,
) -> io::Result<()> {
    write_cipher_metadata(file, cipher_metadata)?;
    write_kdf_metadata(file, kdf_metadata)?;
    Ok(())
}

fn read_metadata(file: &File) -> io::Result<(CipherMetadata<impl AeadCore>, KDFMetadata)> {
    let cipher_metadata = read_cipher_metadata(file)?;
    let kdf_metadata = read_kdf_metadata(file, cipher_metadata.algorithm())?;
    Ok((cipher_metadata, kdf_metadata))
}

pub trait FileEncryptor: AeadCore + AeadInPlace + Sized {
    fn encrypt_file(
        &self,
        input_filename: PathBuf,
        output_filename: PathBuf,
        kdf_metadata: &KDFMetadata,
        cipher_metadata: &CipherMetadata<Self>,
    ) -> Result<(), io::Error> {
        let mut file = File::open(input_filename)?;
        let file_size = file.metadata()?.len() as usize;

        let nonce = Nonce::<Self>::from_slice(cipher_metadata.nonce());

        let mut plaintext = Vec::<u8>::with_capacity(file_size);
        file.read_to_end(&mut plaintext)?;

        let ciphertext = self
            .encrypt(&nonce, plaintext.as_slice())
            .expect("failed to encrypt buffer");

        let mut output_file = File::create(output_filename)?;

        write_metadata(&mut output_file, cipher_metadata, kdf_metadata)?;

        // write encrypted file content
        output_file.write_all(&ciphertext)?;
        Ok(())
    }
}

pub fn decrypt_file(input_filename: PathBuf, passphrase: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut file = File::open(input_filename)?;
    let file_size = file.metadata()?.len() as usize;

    let (cipher_metadata, kdf_metadata) = read_metadata(&file)?;

    // construct encryption key based on key derivation function
    let hash_salt_pair = gen_hash_salt_from_kdf(
        cipher_metadata.algorithm(),
        Some(kdf_metadata.salt()),
        passphrase,
    )?;

    let enc_key_bytes = hash_salt_pair.hash_bytes();

    // nonce should always be 12-byte
    let nonce: [u8; 12] = cipher_metadata.nonce().try_into()?;

    // buffer for decrypted file content
    let mut buf = Vec::with_capacity(file_size * 2);

    // write ciphertext into buffer to decrypt it later
    file.read_to_end(&mut buf)?;

    let res = match cipher_metadata.algorithm() {
        AEADAlgorithm::CHACHA20Poly1305 => {
            let key_nonce_pair = get_chacha20poly1305_key(&enc_key_bytes, Some(&nonce))?;
            let plaintext = key_nonce_pair
                .key()
                .decrypt(key_nonce_pair.nonce(), buf.as_slice());
            plaintext
        }
        AEADAlgorithm::Aes256GCM => {
            let key_nonce_pair = get_aes_256gcm_key(&enc_key_bytes, Some(&nonce))?;
            let plaintext = key_nonce_pair
                .key()
                .decrypt(key_nonce_pair.nonce(), buf.as_slice());
            plaintext
        }
        AEADAlgorithm::Aes128GCM => {
            let key_nonce_pair = get_aes_128gcm_key(&enc_key_bytes, Some(&nonce))?;
            let plaintext = key_nonce_pair
                .key()
                .decrypt(key_nonce_pair.nonce(), buf.as_slice());
            plaintext
        }
    };

    let plaintext = res.map_err(|e| io::Error::new(ErrorKind::InvalidInput, e.to_string()))?;

    Ok(plaintext)
}

impl FileEncryptor for Aes128Gcm {}
impl FileEncryptor for Aes256Gcm {}
impl FileEncryptor for ChaCha20Poly1305 {}
