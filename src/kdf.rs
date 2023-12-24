use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHashString, SaltString};
use argon2::{Argon2, Params, PasswordHasher};

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum KeySize {
    _128bits = 0,
    _256bits = 1,
}

#[derive(Debug, Clone)]
pub struct KDFMetadata {
    salt: SaltString,
}

impl KDFMetadata {
    pub fn new(salt: SaltString) -> Self {
        Self { salt }
    }
    pub fn salt(&self) -> &SaltString {
        &self.salt
    }
}

pub struct Argon2id<'a> {
    argon2id: Argon2<'a>,
}

#[derive(Debug)]
pub struct HashSaltPair {
    salt: SaltString,
    password_hash_string: PasswordHashString,
    hash_bytes: Vec<u8>,
}

impl HashSaltPair {
    fn new(salt: SaltString, hash: PasswordHashString, bytes: Vec<u8>) -> Self {
        Self {
            salt,
            password_hash_string: hash,
            hash_bytes: bytes,
        }
    }

    pub fn hash_bytes(&self) -> &[u8] {
        self.hash_bytes.as_slice()
    }

    pub fn salt(&self) -> &SaltString {
        &self.salt
    }

    pub fn password_hash_string(&self) -> &PasswordHashString {
        &self.password_hash_string
    }
}

impl<'a> Argon2id<'a> {
    pub fn new(key_size: KeySize) -> Self {
        // set hash length based on key size
        let hash_length = match key_size {
            KeySize::_128bits => 16,
            KeySize::_256bits => 32,
        };

        let argon2id = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::default(),
            Params::new(
                // 128 MB
                256 * 1024,
                // 6 number of iterations
                6,
                // degree of parallelism
                8,
                // hash output length
                Some(hash_length),
            )
            .expect("Failed to load argon2 parameters"),
        );
        Self { argon2id }
    }

    pub fn argon2id_hash(
        &self,
        data: &[u8],
        salt: Option<&SaltString>,
    ) -> argon2::password_hash::Result<HashSaltPair> {
        // generate salt (default is 12-byte) salt
        let salt = match salt {
            None => SaltString::generate(&mut OsRng),
            Some(salt) => salt.clone(),
        };

        let password_hash = self.argon2id.hash_password(data, &salt)?;
        let password_hash_string = password_hash.serialize();
        let bytes = Vec::from(password_hash.hash.unwrap().as_bytes());
        let pair = HashSaltPair::new(salt, password_hash_string, bytes);
        Ok(pair)
    }
}
