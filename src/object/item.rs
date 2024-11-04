use std::collections;
use std::iter::Iterator;
use std::time;

use crate::error;
use crate::object::collection;
use crate::object::session;
use crate::object::{SecretServiceChildObject, SecretServiceDbusObject};
use crate::secret;

#[derive(Debug, PartialEq)]
pub struct Item {
    pub attributes: collections::HashMap<String, String>,
    pub created: u64,
    id: uuid::Uuid,
    label: String,
    pub locked: bool,
    pub modified: u64,
    pub parent_path: zvariant::OwnedObjectPath,
    secret: String,
}

#[derive(zvariant::DeserializeDict, zvariant::SerializeDict, zvariant::Type)]
#[zvariant(signature = "dict")]
pub struct ItemReadWriteProperties {
    #[zvariant(rename = "org.freedesktop.Secret.Item.Attributes")]
    pub attributes: collections::HashMap<String, String>,
    #[zvariant(rename = "org.freedesktop.Secret.Item.Label")]
    pub label: String,
}

impl SecretServiceDbusObject for Item {
    fn get_object_path(&self) -> zvariant::OwnedObjectPath {
        let mut object_path = self.parent_path.as_str().to_owned();

        object_path.push('/');
        object_path.push_str(
            self.id
                .as_simple()
                .encode_lower(&mut uuid::Uuid::encode_buffer()),
        );

        zvariant::ObjectPath::from_str_unchecked(&object_path).into()
    }
}

impl SecretServiceChildObject for Item {
    type Parent = collection::Collection;

    fn get_parent_path(&self) -> zvariant::ObjectPath<'_> {
        self.parent_path.as_ref()
    }
}

impl Item {
    pub async fn new<'a, I>(
        id: uuid::Uuid,
        secret: secret::Secret,
        label: &str,
        attributes: I,
        collection: &collection::Collection,
        object_server: &zbus::ObjectServer,
    ) -> Result<Self, error::Error>
    where
        I: Iterator<Item = (&'a str, &'a str)>,
    {
        let created = time::SystemTime::now()
            .duration_since(time::SystemTime::UNIX_EPOCH)
            .expect("current SystemTime before UNIX EPOCH")
            .as_secs();

        let session_interface = session::Session::get_interface_from_object_path(
            &secret.session.as_ref(),
            object_server,
        )
        .await?;
        let session = session_interface.get().await;

        let plaintext = if session.is_encrypted() {
            let iv = secret.parameters;
            let plaintext = session.decrypt(secret.value.as_slice(), iv.as_slice());
            String::from_utf8(plaintext).unwrap()
        } else {
            String::from_utf8(secret.value).unwrap()
        };

        Ok(Self {
            attributes: collections::HashMap::from_iter(
                attributes.map(|(key, value)| (key.to_string(), value.to_string())),
            ),
            created,
            id,
            label: label.to_owned(),
            locked: true,
            modified: created,
            parent_path: collection.get_object_path().clone(),
            secret: plaintext,
        })
    }

    pub fn get_secret_with_session(&self, session: &session::Session) -> secret::Secret {
        let secret = if session.is_encrypted() {
            let (ciphertext, iv) = session.encrypt(self.secret.as_bytes());
            secret::Secret {
                session: session.get_object_path(),
                value: ciphertext,
                parameters: iv,
                content_type: "text/plain; charset=utf8".to_owned(),
            }
        } else {
            secret::Secret {
                session: session.get_object_path(),
                value: self.secret.as_bytes().to_vec(),
                parameters: Vec::new(),
                content_type: "text/plain; charset=utf8".to_owned(),
            }
        };
        secret
    }

    pub fn set_secret_with_session(&mut self, secret: secret::Secret, session: &session::Session) {
        // TODO: Check for decryption errors.
        let plaintext = if session.is_encrypted() {
            let iv = secret.parameters;
            let plaintext = session.decrypt(secret.value.as_slice(), iv.as_slice());
            String::from_utf8(plaintext).unwrap()
        } else {
            String::from_utf8(secret.value).unwrap()
        };
        self.secret = plaintext;
    }
}

#[zbus::interface(name = "org.freedesktop.Secret.Item")]
impl Item {
    /// Delete method
    pub async fn delete(
        &mut self,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
        #[zbus(signal_emitter)] emitter: zbus::object_server::SignalEmitter<'_>,
    ) -> Result<zvariant::ObjectPath<'_>, error::Error> {
        self.remove::<Item>(object_server).await?;
        let removed = self.remove_from_parent(object_server).await;

        if removed {
            let item_path = self.get_object_path();
            log::info!("Deleted item on '{item_path}'");
            collection::Collection::item_deleted(&emitter).await?;
        }

        Ok(zvariant::ObjectPath::from_str_unchecked("/"))
    }

    /// GetSecret method
    pub async fn get_secret(
        &self,
        session: zvariant::ObjectPath<'_>,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
    ) -> Result<secret::Secret, error::Error> {
        let session_path = session;
        let session_interface =
            session::Session::get_interface_from_object_path(&session_path, object_server).await?;
        let session = session_interface.get().await;

        let secret = self.get_secret_with_session(&session);
        Ok(secret)
    }

    /// SetSecret method
    pub async fn set_secret(
        &mut self,
        secret: secret::Secret,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
        #[zbus(signal_emitter)] emitter: zbus::object_server::SignalEmitter<'_>,
    ) -> Result<(), error::Error> {
        let session_path = secret.session.as_ref();
        let session_interface =
            session::Session::get_interface_from_object_path(&session_path, object_server).await?;
        let session = session_interface.get().await;

        self.set_secret_with_session(secret, &session);
        collection::Collection::item_changed(&emitter).await?;

        Ok(())
    }

    /// Attributes property
    #[zbus(property)]
    fn attributes(&self) -> collections::HashMap<&str, &str> {
        self.attributes
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect()
    }

    #[zbus(property)]
    async fn set_attributes(&mut self, value: collections::HashMap<String, String>) {
        self.attributes = value;
    }

    /// Created property
    #[zbus(property)]
    fn created(&self) -> u64 {
        self.created
    }

    /// Label property
    #[zbus(property)]
    fn label(&self) -> &str {
        &self.label
    }

    #[zbus(property)]
    fn set_label(&mut self, value: &str) {
        self.label = value.to_owned();
    }

    /// Locked property
    #[zbus(property)]
    pub fn locked(&self) -> bool {
        self.locked
    }

    /// Modified property
    #[zbus(property)]
    fn modified(&self) -> u64 {
        self.modified
    }
}
