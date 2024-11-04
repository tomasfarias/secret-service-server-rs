use std::collections;
use std::iter::Iterator;
use std::time;

use crate::error;
use crate::object::item;
use crate::object::service;
use crate::object::{SecretServiceChildObject, SecretServiceDbusObject, SecretServiceParentObject};
use crate::secret;

#[derive(Debug, PartialEq)]
pub struct Collection {
    pub alias: Option<String>,
    pub created: u64,
    id: uuid::Uuid,
    pub label: String,
    pub locked: bool,
    pub items: collections::HashSet<zvariant::OwnedObjectPath>,
    pub items_with_attributes:
        collections::HashMap<zvariant::OwnedObjectPath, collections::HashSet<(String, String)>>,
    pub modified: u64,
    pub parent_path: zvariant::OwnedObjectPath,
}

#[derive(zvariant::DeserializeDict, zvariant::SerializeDict, zvariant::Type)]
#[zvariant(signature = "dict")]
pub struct CollectionReadWriteProperties {
    #[zvariant(rename = "org.freedesktop.Secret.Collection.Label")]
    pub label: String,
}

impl SecretServiceDbusObject for Collection {
    fn get_object_path(&self) -> zvariant::OwnedObjectPath {
        if let Some(alias) = &self.alias {
            if alias == "default" {
                return zvariant::ObjectPath::from_str_unchecked(
                    "/org/freedesktop/secrets/aliases/default",
                )
                .into();
            }
        }

        let mut object_path = "/org/freedesktop/secrets/collection/".to_owned();
        object_path.push_str(
            self.id
                .as_simple()
                .encode_lower(&mut uuid::Uuid::encode_buffer()),
        );

        zvariant::ObjectPath::from_str_unchecked(&object_path).into()
    }
}

impl SecretServiceParentObject for Collection {
    fn get_children(&self) -> &collections::HashSet<zvariant::OwnedObjectPath> {
        &self.items
    }

    fn get_mut_children(&mut self) -> &mut collections::HashSet<zvariant::OwnedObjectPath> {
        &mut self.items
    }
}

impl SecretServiceChildObject for Collection {
    type Parent = service::Service;

    fn get_parent_path(&self) -> zvariant::ObjectPath<'_> {
        self.parent_path.as_ref()
    }
}

impl Collection {
    pub fn new(
        id: uuid::Uuid,
        label: &str,
        alias: Option<&str>,
        service: &service::Service,
    ) -> Self {
        let created = time::SystemTime::now()
            .duration_since(time::SystemTime::UNIX_EPOCH)
            .expect("current SystemTime before UNIX EPOCH")
            .as_secs();

        Self {
            id,
            alias: alias.map(|s| s.to_owned()),
            created,
            items: collections::HashSet::new(),
            label: label.to_owned(),
            locked: true,
            items_with_attributes: collections::HashMap::new(),
            modified: created,
            parent_path: service.get_object_path().clone(),
        }
    }

    pub fn new_default(service: &service::Service) -> Self {
        let created = time::SystemTime::now()
            .duration_since(time::SystemTime::UNIX_EPOCH)
            .expect("current SystemTime before UNIX EPOCH")
            .as_secs();

        Self {
            id: uuid::Uuid::new_v4(),
            alias: Some("default".to_string()),
            created,
            items: collections::HashSet::new(),
            label: "default".to_string(),
            locked: true,
            items_with_attributes: collections::HashMap::new(),
            modified: created,
            parent_path: service.get_object_path().clone(),
        }
    }

    pub fn insert_item<'a, I>(
        &mut self,
        item_object_path: zvariant::OwnedObjectPath,
        attributes: I,
        replace: bool,
    ) where
        I: Iterator<Item = (&'a str, &'a str)>,
    {
        let attributes_set: collections::HashSet<(String, String)> = attributes
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect();

        if replace {
            self.items_with_attributes
                .retain(|_, value| value == &attributes_set);

            self.items
                .retain(|value| self.items_with_attributes.contains_key(value));
        }

        self.items.insert(item_object_path.clone());
        self.items_with_attributes
            .insert(item_object_path.clone(), attributes_set);
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
        let attributes: Vec<(String, String)> = properties
            .attributes
            .iter()
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect();

        let item_id = uuid::Uuid::new_v4();
        let new_item = item::Item::new(
            item_id,
            secret,
            &properties.label,
            attributes
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_str())),
            self,
            object_server,
        )
        .await?;
        let (item_path, is_new) = new_item.serve_at(object_server).await?;

        if is_new {
            emitter.item_created().await?;
        } else {
            emitter.item_changed().await?;
        }
        service::Service::collection_changed(&emitter).await?;

        log::info!("Created new item on '{item_path}'");
        self.insert_item(
            item_path.clone(),
            attributes
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_str())),
            replace,
        );

        Ok((
            item_path.into(),
            zvariant::ObjectPath::from_str_unchecked("/"),
        ))
    }

    /// Delete method
    pub async fn delete(
        &mut self,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
        #[zbus(signal_emitter)] emitter: zbus::object_server::SignalEmitter<'_>,
    ) -> Result<zvariant::ObjectPath<'_>, error::Error> {
        for item in self.get_mut_children().iter() {
            if let Ok(item_interface) =
                item::Item::get_interface_from_object_path(&item, object_server).await
            {
                let mut item = item_interface.get_mut().await;
                item.delete(object_server, item_interface.signal_emitter().to_owned())
                    .await?;
            }
        }

        self.remove::<Collection>(object_server).await?;

        let removed = self.remove_from_parent(object_server).await;

        if removed {
            let collection_path = self.get_object_path();
            log::info!("Deleted collection on '{collection_path}'");
            service::Service::collection_deleted(&emitter).await?;
        }

        Ok(zvariant::ObjectPath::from_str_unchecked("/"))
    }

    /// SearchItems method
    fn search_items(
        &self,
        attributes: collections::HashMap<String, String>,
    ) -> Vec<zvariant::ObjectPath<'_>> {
        let attributes_set: collections::HashSet<(String, String)> = attributes
            .iter()
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect();

        self.items_with_attributes
            .iter()
            .filter_map(|(key, value)| {
                if value == &attributes_set {
                    Some(key.as_ref())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Created property
    #[zbus(property)]
    fn created(&self) -> u64 {
        self.created
    }

    /// Items property
    #[zbus(property)]
    fn items(&self) -> Vec<zvariant::ObjectPath<'_>> {
        self.get_children()
            .iter()
            .map(|path| path.as_ref())
            .collect()
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
    fn locked(&self) -> bool {
        self.locked
    }

    /// Modified property
    #[zbus(property)]
    fn modified(&self) -> u64 {
        self.modified
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
}
