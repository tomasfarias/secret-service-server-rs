//! # D-Bus interface proxy for: `org.freedesktop.Secret.Collection`
use std::collections;
use std::time;

use crate::error;
use crate::item;
use crate::secret;
use crate::service;

#[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct Collection {
    pub alias: Option<String>,
    pub created: u64,
    deleted: bool,
    pub items: collections::HashMap<String, item::Item>,
    pub label: String,
    pub locked: bool,
    pub lookup_attributes: collections::HashMap<(String, String), collections::HashSet<String>>,
    pub modified: u64,
    pub object_path: zvariant::OwnedObjectPath,
    pub parent_path: zvariant::OwnedObjectPath,
}

#[derive(zvariant::DeserializeDict, zvariant::SerializeDict, zvariant::Type)]
#[zvariant(signature = "dict")]
pub struct CollectionReadWriteProperties {
    #[zvariant(rename = "org.freedesktop.Secret.Collection.Label")]
    pub label: String,
}

impl Collection {
    pub fn new(
        id: &uuid::Uuid,
        label: &str,
        alias: Option<&str>,
        service: &service::Service,
    ) -> Self {
        let mut object_path = "/org/freedesktop/secrets/collection/".to_owned();
        object_path.push_str(
            id.as_simple()
                .encode_lower(&mut uuid::Uuid::encode_buffer()),
        );
        let path = zvariant::OwnedObjectPath::try_from(object_path).unwrap();

        let created = time::SystemTime::now()
            .duration_since(time::SystemTime::UNIX_EPOCH)
            .expect("current SystemTime before UNIX EPOCH")
            .as_secs();

        Self {
            alias: alias.map(|s| s.to_owned()),
            created,
            deleted: false,
            items: collections::HashMap::new(),
            label: label.to_owned(),
            locked: true,
            lookup_attributes: collections::HashMap::new(),
            modified: created,
            object_path: path,
            parent_path: service.object_path.clone(),
        }
    }

    pub fn error_if_deleted(&self) -> Result<(), error::Error> {
        if self.deleted == true {
            Err(error::Error::CollectionIsDeleted)
        } else {
            Ok(())
        }
    }

    /// Attempt to add or update an `item::Item` to this collection and, if
    /// successful, returns a tuple containing a reference to the item added
    /// and a `bool` indicating if an item existed and was updated.
    ///
    /// A clone of the `item::Item`'s object path will be used as a key.
    /// If the underlying map contains an `item::Item` with the same key and
    /// `replace` is `false`, then an error is returned.
    pub fn try_add_item(
        &mut self,
        item: item::Item,
        replace: bool,
    ) -> Result<(&item::Item, bool), error::Error> {
        let key = item.object_path.as_ref().to_string();
        let should_replace = self.items.contains_key(&key);

        if should_replace && !replace {
            Err(error::Error::ItemExists(key))
        } else {
            if should_replace {
                let existing_item = self
                    .items
                    .remove(&key)
                    .expect("key must exist as we already checked");
                self.remove_lookup_attributes(
                    &existing_item.object_path.as_ref(),
                    &existing_item.attributes,
                );
            }
            self.add_lookup_attributes(&item.object_path.as_ref(), &item.attributes);
            self.items.insert(key.clone(), item);

            Ok((
                self.items
                    .get(&key)
                    .expect("key must exist as it was just inserted"),
                should_replace,
            ))
        }
    }

    pub fn add_lookup_attributes(
        &mut self,
        object_path: &zvariant::ObjectPath<'_>,
        attributes: &collections::HashMap<String, String>,
    ) {
        let item_object_path = object_path.as_ref().to_string();

        for (key, value) in attributes {
            let lookup_attributes_key = (key.clone(), value.clone());

            match self.lookup_attributes.get_mut(&lookup_attributes_key) {
                Some(paths) => {
                    (*paths).insert(item_object_path.clone());
                }
                None => {
                    let mut new_set = collections::HashSet::new();
                    new_set.insert(item_object_path.clone());
                    self.lookup_attributes
                        .insert(lookup_attributes_key, new_set);
                }
            }
        }
    }

    pub fn remove_lookup_attributes(
        &mut self,
        object_path: &zvariant::ObjectPath<'_>,
        attributes: &collections::HashMap<String, String>,
    ) {
        let item_object_path = object_path.as_ref().to_string();

        for (key, value) in attributes {
            let lookup_attributes_key = (key.clone(), value.clone());

            if let Some(paths) = self.lookup_attributes.get_mut(&lookup_attributes_key) {
                (*paths).remove(&item_object_path);
            }
        }
    }

    pub async fn emit_deleted(
        &self,
        object_server: &zbus::ObjectServer,
    ) -> Result<(), error::Error> {
        let service_ref = object_server
            .interface::<_, service::Service>(&self.parent_path)
            .await?;
        let mut service = service_ref.get_mut().await;
        service
            .collections
            .remove(&self.object_path.as_ref().to_string());
        service::Service::collection_deleted(service_ref.signal_emitter()).await?;
        Ok(())
    }
}

#[zbus::interface(name = "org.freedesktop.Secret.Collection")]
impl Collection {
    /// CreateItem method
    async fn create_item(
        &mut self,
        properties: item::ItemReadWriteProperties,
        secret: secret::Secret,
        replace: bool,
        #[zbus(signal_emitter)] emitter: zbus::object_server::SignalEmitter<'_>,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
    ) -> Result<(zvariant::ObjectPath<'_>, zvariant::ObjectPath<'_>), error::Error> {
        self.error_if_deleted()?;

        let new_item = item::Item::new(
            secret,
            &properties.label,
            Some(properties.attributes),
            &self,
            object_server,
        )
        .await?;
        let (added_item, replaced) = self.try_add_item(new_item, replace)?;

        if replaced {
            emitter.item_changed().await?;
        } else {
            emitter.item_created().await?;
        }

        Ok((
            added_item.object_path.as_ref(),
            zvariant::ObjectPath::try_from("/").unwrap(),
        ))
    }

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

    /// SearchItems method
    fn search_items(
        &self,
        attributes: collections::HashMap<String, String>,
    ) -> Result<Vec<zvariant::OwnedObjectPath>, error::Error> {
        self.error_if_deleted()?;

        Ok(attributes
            .iter()
            .filter_map(|(key, value)| {
                let attributes_key = (key.clone(), value.clone());

                if let Some(paths) = self.lookup_attributes.get(&attributes_key) {
                    Some(paths.iter().map(|s| {
                        zvariant::OwnedObjectPath::try_from(s.clone())
                            .expect("path stored should be valid")
                    }))
                } else {
                    None
                }
            })
            .flatten()
            .collect())
    }

    /// ItemChanged signal
    #[zbus(signal)]
    pub async fn item_changed(emitter: &zbus::object_server::SignalEmitter<'_>)
        -> zbus::Result<()>;

    /// ItemCreated signal
    #[zbus(signal)]
    async fn item_created(emitter: &zbus::object_server::SignalEmitter<'_>) -> zbus::Result<()>;

    /// ItemDeleted signal
    #[zbus(signal)]
    pub async fn item_deleted(emitter: &zbus::object_server::SignalEmitter<'_>)
        -> zbus::Result<()>;

    /// Created property
    #[zbus(property)]
    fn created(&self) -> Result<u64, zbus::fdo::Error> {
        self.error_if_deleted()?;

        Ok(self.created)
    }

    /// Items property
    #[zbus(property)]
    fn items(&self) -> Result<Vec<zvariant::OwnedObjectPath>, zbus::fdo::Error> {
        self.error_if_deleted()?;

        Ok(self
            .items
            .keys()
            .map(|key| zvariant::OwnedObjectPath::try_from(key.as_str()).unwrap())
            .collect())
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
