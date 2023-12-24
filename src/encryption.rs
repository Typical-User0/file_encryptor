use crate::kdf::{Argon2id, HashSaltPair, KeySize};
use aes_gcm::aead::Nonce;
use aes_gcm::{
    aead::{AeadCore, KeyInit, OsRng},
    Aes128Gcm, Aes256Gcm,
};
use argon2::password_hash::SaltString;
use chacha20poly1305::ChaCha20Poly1305;
use clap::ValueEnum;
use std::error::Error;
use std::fmt::Debug;

#[repr(u8)]
#[derive(Copy, Debug, Clone, ValueEnum)]
pub enum AEADAlgorithm {
    Aes128GCM = 0,
    Aes256GCM = 1,
    CHACHA20Poly1305 = 2,
}

impl TryFrom<u8> for AEADAlgorithm {
    type Error = ();

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            x if x == AEADAlgorithm::Aes128GCM as u8 => Ok(AEADAlgorithm::Aes128GCM),
            x if x == AEADAlgorithm::Aes256GCM as u8 => Ok(AEADAlgorithm::Aes256GCM),
            x if x == AEADAlgorithm::CHACHA20Poly1305 as u8 => Ok(AEADAlgorithm::CHACHA20Poly1305),
            _ => Err(()),
        }
    }
}

#[derive(Debug)]
pub struct KeyNoncePair<Key: AeadCore> {
    key: Key,
    nonce: Nonce<Key>,
}

#[derive(Debug, Clone)]
pub struct CipherMetadata<T: AeadCore> {
    algorithm: AEADAlgorithm,
    nonce: Nonce<T>, // nonce will be always 96 bits (12 bytes)
}

impl<T: AeadCore> CipherMetadata<T> {
    pub fn new(algorithm: AEADAlgorithm, nonce: Nonce<T>) -> Self {
        Self { algorithm, nonce }
    }

    pub fn algorithm(&self) -> AEADAlgorithm {
        self.algorithm
    }

    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }
}

impl<Key: AeadCore> KeyNoncePair<Key> {
    fn new(key: Key, nonce: Nonce<Key>) -> Self {
        KeyNoncePair { key, nonce }
    }

    pub fn key(&self) -> &Key {
        &self.key
    }

    pub fn nonce(&self) -> &Nonce<Key> {
        &self.nonce
    }
}

pub fn get_aes_128gcm_key(
    bytes: &[u8],
    nonce: Option<&[u8; 12]>,
) -> Result<KeyNoncePair<Aes128Gcm>, Box<dyn Error>> {
    let key: [u8; 16] = bytes.try_into()?;
    let key: aes_gcm::Key<Aes128Gcm> = key.into();
    let key = Aes128Gcm::new(&key);
    let nonce = if let Some(nonce) = nonce {
        *Nonce::<Aes128Gcm>::from_slice(nonce)
    } else {
        Aes128Gcm::generate_nonce(&mut OsRng)
    };
    let key_nonce_pair = KeyNoncePair::new(key, nonce);

    Ok(key_nonce_pair)
}

pub fn get_aes_256gcm_key(
    bytes: &[u8],
    nonce: Option<&[u8; 12]>,
) -> Result<KeyNoncePair<Aes256Gcm>, Box<dyn Error>> {
    let key: [u8; 32] = bytes.try_into()?;
    let key: aes_gcm::Key<Aes256Gcm> = key.into();
    let key = Aes256Gcm::new(&key);

    let nonce = if let Some(nonce) = nonce {
        *Nonce::<Aes256Gcm>::from_slice(nonce)
    } else {
        Aes256Gcm::generate_nonce(&mut OsRng)
    };

    let key_nonce_pair = KeyNoncePair::new(key, nonce);
    Ok(key_nonce_pair)
}

pub fn get_chacha20poly1305_key(
    bytes: &[u8],
    nonce: Option<&[u8; 12]>,
) -> Result<KeyNoncePair<ChaCha20Poly1305>, Box<dyn Error>> {
    let key: [u8; 32] = bytes.try_into()?;
    let key = chacha20poly1305::Key::from_slice(&key);
    let key = ChaCha20Poly1305::new(key);

    let nonce = if let Some(nonce) = nonce {
        *Nonce::<ChaCha20Poly1305>::from_slice(nonce)
    } else {
        ChaCha20Poly1305::generate_nonce(&mut OsRng)
    };

    let key_nonce_pair = KeyNoncePair::new(key, nonce);
    Ok(key_nonce_pair)
}

pub fn gen_hash_salt_from_kdf(
    algorithm: AEADAlgorithm,
    salt: Option<&SaltString>,
    passphrase: &[u8],
) -> Result<HashSaltPair, Box<dyn Error>> {
    let key_size = match algorithm {
        // 128 bits = 16 bytes
        AEADAlgorithm::Aes128GCM => KeySize::_128bits,
        // 256 bits = 32 bytes
        AEADAlgorithm::CHACHA20Poly1305 | AEADAlgorithm::Aes256GCM => KeySize::_256bits,
    };

    let argon2id = Argon2id::new(key_size);

    let hash_salt_pair = argon2id
        .argon2id_hash(passphrase, salt)
        .expect("Failed to create key from passphrase");

    Ok(hash_salt_pair)
}
