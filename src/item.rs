//! Implementation of `org.freedesktop.Secret.Item` D-Bus interface.
//!
//!
use std::collections;
use std::time;

use crate::collection;
use crate::collection::CollectionSignals;
use crate::error;
use crate::secret;
use crate::service;

#[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct Item {
    pub attributes: collections::HashMap<String, String>,
    pub created: u64,
    deleted: bool,
    label: String,
    pub locked: bool,
    pub modified: u64,
    pub object_path: zvariant::OwnedObjectPath,
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

impl Item {
    pub async fn new(
        secret: secret::Secret,
        label: &str,
        attributes: Option<collections::HashMap<String, String>>,
        collection: &collection::Collection,
        object_server: &zbus::ObjectServer,
    ) -> Result<Self, error::Error> {
        let created = time::SystemTime::now()
            .duration_since(time::SystemTime::UNIX_EPOCH)
            .expect("current SystemTime before UNIX EPOCH")
            .as_secs();

        let parent_path = collection.object_path.clone();

        let collection_ref = object_server
            .interface::<_, collection::Collection>(&parent_path)
            .await?;
        let collection = collection_ref.get().await;
        let service_path = collection.parent_path.clone();
        let service_ref = object_server
            .interface::<_, service::Service>(&service_path)
            .await?;
        let service = service_ref.get().await;

        let session = service
            .sessions
            .get(&secret.session.as_ref().to_string())
            .unwrap();

        let plaintext = if session.is_encrypted() {
            let iv = secret.parameters;
            let plaintext = session.decrypt(secret.value.as_slice(), iv.as_slice());
            String::from_utf8(plaintext).unwrap()
        } else {
            String::from_utf8(secret.value).unwrap()
        };

        Ok(Self {
            attributes: attributes.unwrap_or_else(collections::HashMap::new),
            created,
            deleted: false,
            label: label.to_owned(),
            locked: true,
            modified: created,
            object_path: zvariant::OwnedObjectPath::default(),
            parent_path,
            secret: plaintext,
        })
    }

    pub fn error_if_deleted(&self) -> Result<(), error::Error> {
        if self.deleted == true {
            Err(error::Error::ItemIsDeleted(
                self.object_path.as_str().to_owned(),
            ))
        } else {
            Ok(())
        }
    }

    pub async fn emit_deleted(
        &self,
        object_server: &zbus::ObjectServer,
    ) -> Result<(), error::Error> {
        let collection_ref = object_server
            .interface::<_, collection::Collection>(&self.parent_path)
            .await?;
        let mut collection = collection_ref.get_mut().await;
        collection
            .items
            .remove(&self.object_path.as_ref().to_string());
        collection::Collection::item_deleted(collection_ref.signal_emitter()).await?;

        Ok(())
    }
}

#[zbus::interface(name = "org.freedesktop.Secret.Item")]
impl Item {
    /// Delete method
    async fn delete(
        &mut self,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
    ) -> Result<zvariant::ObjectPath<'_>, error::Error> {
        self.error_if_deleted()?;

        self.emit_deleted(object_server).await?;
        self.deleted = true;

        Ok(zvariant::ObjectPath::try_from("/").unwrap())
    }

    /// GetSecret method
    pub async fn get_secret(
        &self,
        session: zvariant::ObjectPath<'_>,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
    ) -> Result<secret::Secret, error::Error> {
        self.error_if_deleted()?;
        let session_path = session;

        let collection_ref = object_server
            .interface::<_, collection::Collection>(&self.parent_path)
            .await?;
        let collection = collection_ref.get().await;
        let service_path = collection.parent_path.clone();
        let service_ref = object_server
            .interface::<_, service::Service>(&service_path)
            .await?;
        let service = service_ref.get().await;

        let session = service
            .sessions
            .get(&session_path.as_ref().to_string())
            .unwrap();

        let secret = if session.is_encrypted() {
            let (ciphertext, iv) = session.encrypt(self.secret.as_bytes());
            secret::Secret {
                session: session_path.into(),
                value: ciphertext,
                parameters: iv,
                content_type: "balls".to_owned(),
            }
        } else {
            secret::Secret {
                session: session_path.into(),
                value: self.secret.as_bytes().to_vec(),
                parameters: Vec::new(),
                content_type: "balls".to_owned(),
            }
        };

        Ok(secret)
    }

    /// SetSecret method
    async fn set_secret(
        &mut self,
        secret: secret::Secret,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
        #[zbus(signal_emitter)] emitter: zbus::object_server::SignalEmitter<'_>,
    ) -> Result<(), error::Error> {
        self.error_if_deleted()?;

        let collection_ref = object_server
            .interface::<_, collection::Collection>(&self.parent_path)
            .await?;
        let collection = collection_ref.get().await;
        let service_path = collection.parent_path.clone();
        let service_ref = object_server
            .interface::<_, service::Service>(&service_path)
            .await?;
        let service = service_ref.get().await;

        let session = service
            .sessions
            .get(&secret.session.as_ref().to_string())
            .unwrap();

        let plaintext = if session.is_encrypted() {
            let iv = secret.parameters;
            let plaintext = session.decrypt(secret.value.as_slice(), iv.as_slice());
            String::from_utf8(plaintext).unwrap()
        } else {
            String::from_utf8(secret.value).unwrap()
        };

        self.secret = plaintext;

        emitter.item_changed().await?;

        Ok(())
    }

    /// Attributes property
    #[zbus(property)]
    fn attributes(&self) -> Result<collections::HashMap<String, String>, zbus::fdo::Error> {
        self.error_if_deleted()?;

        Ok(self.attributes.clone())
    }

    #[zbus(property)]
    async fn set_attributes(
        &mut self,
        value: collections::HashMap<String, String>,
    ) -> Result<(), zbus::fdo::Error> {
        self.error_if_deleted()?;
        // let attributes: collections::HashMap<String, String> = value
        //     .iter()
        //     .map(|(k, v)| return (k.clone(), v.clone()))
        //     .collect();
        self.attributes = value;
        Ok(())
    }

    /// Created property
    #[zbus(property)]
    fn created(&self) -> Result<u64, zbus::fdo::Error> {
        self.error_if_deleted()?;

        Ok(self.created)
    }

    /// Label property
    #[zbus(property)]
    fn label(&self) -> Result<&str, zbus::fdo::Error> {
        self.error_if_deleted()?;

        Ok(&self.label)
    }

    #[zbus(property)]
    fn set_label(&mut self, value: &str) -> Result<(), zbus::fdo::Error> {
        self.error_if_deleted()?;

        self.label = value.to_owned();
        Ok(())
    }

    /// Locked property
    #[zbus(property)]
    fn locked(&self) -> Result<bool, zbus::fdo::Error> {
        self.error_if_deleted()?;

        Ok(self.locked)
    }

    /// Modified property
    #[zbus(property)]
    fn modified(&self) -> Result<u64, zbus::fdo::Error> {
        self.error_if_deleted()?;

        Ok(self.modified)
    }
}
