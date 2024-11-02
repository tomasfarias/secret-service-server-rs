//! Implementation of `org.freedesktop.Secret.Session` D-Bus interface.
//!
//! The state tracked by the `Session` is used to encrypt and decrypt
//! secrets. So, although not part of the `org.freedesktop.Secret.Session`
//! D-Bus interface, we implement encryption and decryption methods here.
use aes::cipher::{block_padding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hkdf;
use sha2;

use crate::error;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

/// Supported encryption algorithms.
///
/// Based on: https://specifications.freedesktop.org/secret-service-spec/latest/transfer-secrets.html,
/// only two algorithms are supported: `Algorithm::Plain` or `Algorithm::Dh`
/// short for dh-ietf1024-sha256-aes128-cbc-pkcs7.
#[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub enum Algorithm {
    Plain,
    Dh { aes_key: [u8; 16] },
}

impl Algorithm {
    pub fn encrypt(&self, plaintext: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let iv = [0x24; 16];

        match self {
            Algorithm::Dh { aes_key } => {
                let ciphertext = Aes128CbcEnc::new(aes_key.into(), &iv.into())
                    .encrypt_padded_vec_mut::<block_padding::Pkcs7>(plaintext);
                (ciphertext, iv.into())
            }
            Algorithm::Plain => (plaintext.to_vec(), Vec::new()),
        }
    }

    pub fn decrypt(&self, ciphertext: &[u8], iv: &[u8]) -> Vec<u8> {
        match self {
            Algorithm::Dh { aes_key } => {
                let plaintext = Aes128CbcDec::new(aes_key.into(), iv.into())
                    .decrypt_padded_vec_mut::<block_padding::Pkcs7>(ciphertext)
                    .unwrap();
                plaintext
            }
            Algorithm::Plain => ciphertext.to_vec(),
        }
    }
}

#[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct Session {
    pub algorithm: Algorithm,
    closed: bool,
    pub object_path: zvariant::OwnedObjectPath,
}

/// Builder pattern implementation for `Session`.
///
/// This allows separating the encryption algorithm setup (when necessary).
pub struct SessionBuilder {
    object_path: zvariant::OwnedObjectPath,
}

impl SessionBuilder {
    pub fn plain(self) -> Session {
        Session {
            algorithm: Algorithm::Plain,
            closed: false,
            object_path: self.object_path,
        }
    }

    pub fn dh(self, client_public_key: [u8; 32]) -> (Session, [u8; 32]) {
        let secret = x25519_dalek::EphemeralSecret::random();
        let public_key = x25519_dalek::PublicKey::from(&secret);

        let shared_secret =
            secret.diffie_hellman(&x25519_dalek::PublicKey::from(client_public_key));
        let shared_secret_bytes = shared_secret.to_bytes();

        let mut shared_secret_padded = vec![0u8; 128 - shared_secret_bytes.len()];
        shared_secret_padded.extend_from_slice(&shared_secret_bytes);

        let info = [];
        let salt = None;

        let (_, hk) = hkdf::Hkdf::<sha2::Sha256>::extract(salt, &shared_secret_padded);
        let mut output = [0; 16];
        hk.expand(&info, &mut output).unwrap();

        (
            Session {
                algorithm: Algorithm::Dh {
                    aes_key: output.into(),
                },
                closed: false,
                object_path: self.object_path,
            },
            public_key.to_bytes(),
        )
    }
}

impl Session {
    pub fn new(id: &uuid::Uuid) -> SessionBuilder {
        let mut object_path = "/org/freedesktop/secrets/session/".to_owned();
        object_path.push_str(
            id.as_simple()
                .encode_lower(&mut uuid::Uuid::encode_buffer()),
        );
        let path = zvariant::OwnedObjectPath::try_from(object_path).unwrap();

        SessionBuilder { object_path: path }
    }

    pub fn error_if_closed(&self) -> Result<(), error::Error> {
        if self.closed == true {
            Err(error::Error::SessionIsClosed)
        } else {
            Ok(())
        }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> (Vec<u8>, Vec<u8>) {
        self.algorithm.encrypt(plaintext)
    }

    pub fn decrypt(&self, ciphertext: &[u8], iv: &[u8]) -> Vec<u8> {
        self.algorithm.decrypt(ciphertext, iv)
    }

    pub fn is_encrypted(&self) -> bool {
        match self.algorithm {
            Algorithm::Dh { aes_key: _ } => true,
            Algorithm::Plain => false,
        }
    }
}

#[zbus::interface(name = "org.freedesktop.Secret.Session")]
impl Session {
    /// Close method
    fn close(&mut self) -> Result<(), error::Error> {
        self.error_if_closed()?;

        self.closed = true;

        Ok(())
    }
}
