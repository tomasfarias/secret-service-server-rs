//! Implementation of `org.freedesktop.Secret.Session` D-Bus interface.
//!
//! The state tracked by the `Session` is used to encrypt and decrypt
//! secrets. So, although not part of the `org.freedesktop.Secret.Session`
//! D-Bus interface, we implement encryption and decryption methods here.
use aes::cipher::{block_padding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};

use crate::error;
use crate::object::SecretServiceDbusObject;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

/// Supported encryption algorithms.
///
/// Based on: https://specifications.freedesktop.org/secret-service-spec/latest/transfer-secrets.html,
/// only two algorithms are supported: `Algorithm::Plain` or `Algorithm::Dh`
/// short for dh-ietf1024-sha256-aes128-cbc-pkcs7.
#[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize, Clone, Copy)]
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
            Algorithm::Dh { aes_key } => Aes128CbcDec::new(aes_key.into(), iv.into())
                .decrypt_padded_vec_mut::<block_padding::Pkcs7>(ciphertext)
                .unwrap(),
            Algorithm::Plain => ciphertext.to_vec(),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct Session {
    pub algorithm: Algorithm,
    id: uuid::Uuid,
}

impl SecretServiceDbusObject for Session {
    fn get_object_path(&self) -> zvariant::OwnedObjectPath {
        let mut object_path = "/org/freedesktop/secrets/session/".to_owned();
        object_path.push_str(
            self.id
                .as_simple()
                .encode_lower(&mut uuid::Uuid::encode_buffer()),
        );
        zvariant::ObjectPath::from_str_unchecked(&object_path).into()
    }

    /// Override default trait method implementation to provide a better error.
    ///
    /// A `Session` not found should return a `NoSession` error instead of the
    /// generic `NoSuchObject`.
    async fn get_interface_from_object_path<'p>(
        object_path: &'p zvariant::ObjectPath<'_>,
        object_server: &'p zbus::ObjectServer,
    ) -> Result<zbus::object_server::InterfaceRef<Session>, error::Error> {
        let interface_ref = object_server
            .interface::<_, Self>(object_path)
            .await
            .map_err(|_| error::Error::NoSession(object_path.as_str().to_owned()))?;
        Ok(interface_ref)
    }
}

impl Session {
    pub fn new_plain() -> Session {
        Session {
            algorithm: Algorithm::Plain,
            id: uuid::Uuid::new_v4(),
        }
    }

    pub fn new_dh(client_public_key: [u8; 32]) -> Result<(Session, [u8; 32]), error::Error> {
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
        hk.expand(&info, &mut output)?;

        Ok((
            Session {
                algorithm: Algorithm::Dh { aes_key: output },
                id: uuid::Uuid::new_v4(),
            },
            public_key.to_bytes(),
        ))
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
    async fn close(
        &mut self,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
    ) -> Result<(), error::Error> {
        self.remove::<Session>(object_server).await?;
        Ok(())
    }
}
