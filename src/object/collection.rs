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
                item::Item::get_interface_from_object_path(item, object_server).await
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret;
    use crate::server;

    use std::time;
    use uuid;

    /// Run a `org.freedesktop.Secret.Service` server.
    ///
    /// This coroutine is meant to be awaited at the beginning of each test
    /// function that will be making calls to test the server.
    /// It returns a handle that **must** be aborted once the test is done,
    /// as otherwise the task **runs forever**.
    async fn run_service_server() -> (String, tokio::task::JoinHandle<()>) {
        let start_event = event_listener::Event::new();
        let start_event_listener = start_event.listen();
        let mut dbus_name = "org.freedesktop.secrets-test-".to_owned();
        let dbus_id = uuid::Uuid::new_v4();
        dbus_name.push_str(
            dbus_id
                .as_simple()
                .encode_lower(&mut uuid::Uuid::encode_buffer()),
        );

        let cloned_dbus_name = dbus_name.clone();
        let run_server_handle = tokio::spawn(async move {
            let server = server::SecretServiceServer::new(&cloned_dbus_name, start_event)
                .await
                .unwrap();
            server.run().await.unwrap();
        });

        if let Err(_) =
            tokio::time::timeout(time::Duration::from_secs(10), start_event_listener).await
        {
            if run_server_handle.is_finished() {
                run_server_handle.await.unwrap();
                panic!("Server exited early without an error");
            } else {
                panic!("Took to long to start test dbus server");
            }
        }

        (dbus_name, run_server_handle)
    }

    async fn create_collection(
        dbus_name: &str,
        label: &str,
    ) -> Result<zvariant::OwnedObjectPath, error::Error> {
        let connection = zbus::Connection::session().await?;
        let collection_properties = collections::HashMap::from([(
            "org.freedesktop.Secret.Collection.Label",
            zvariant::Value::new(label),
        )]);

        let reply = connection
            .call_method(
                Some(dbus_name),
                "/org/freedesktop/secrets",
                Some("org.freedesktop.Secret.Service"),
                "CreateCollection",
                &(collection_properties, ""),
            )
            .await
            .unwrap();

        let body = reply.body();
        let (collection_object_path, _): (zvariant::ObjectPath<'_>, zvariant::ObjectPath<'_>) =
            body.deserialize().unwrap();

        Ok(collection_object_path.into())
    }

    async fn open_plain_session(
        dbus_name: &str,
    ) -> Result<zvariant::OwnedObjectPath, error::Error> {
        let connection = zbus::Connection::session().await?;

        let reply = connection
            .call_method(
                Some(dbus_name),
                "/org/freedesktop/secrets",
                Some("org.freedesktop.Secret.Service"),
                "OpenSession",
                &("plain", zvariant::Value::from("")),
            )
            .await
            .unwrap();

        let body = reply.body();
        let (_, session_path): (zvariant::Value, zvariant::ObjectPath<'_>) =
            body.deserialize().unwrap();

        Ok(session_path.into())
    }

    #[tokio::test]
    async fn test_create_item() -> Result<(), error::Error> {
        let (dbus_name, run_server_handle) = run_service_server().await;
        let session_path = open_plain_session(dbus_name.as_str()).await?;
        let collection_object_path =
            create_collection(dbus_name.as_str(), "test-collection-label").await?;

        let connection = zbus::Connection::session().await?;
        let item_properties = item::ItemReadWriteProperties {
            attributes: collections::HashMap::new(),
            label: "test-item-label".to_owned(),
        };

        let secret = secret::Secret {
            session: session_path,
            value: "a-very-important-secret".into(),
            parameters: Vec::new(),
            content_type: "text/plain; charset=utf8".to_string(),
        };
        let reply = connection
            .call_method(
                Some(dbus_name.as_str()),
                collection_object_path.as_str(),
                Some("org.freedesktop.Secret.Collection"),
                "CreateItem",
                &(item_properties, secret, false),
            )
            .await
            .unwrap();

        let body = reply.body();
        let (item_object_path, prompt): (zvariant::ObjectPath<'_>, zvariant::ObjectPath<'_>) =
            body.deserialize().unwrap();

        let reply = connection
            .call_method(
                Some(dbus_name.as_str()),
                &item_object_path,
                Some("org.freedesktop.DBus.Properties"),
                "Get",
                &(
                    "org.freedesktop.Secret.Item".to_string(),
                    "Label".to_string(),
                ),
            )
            .await
            .unwrap();

        let body = reply.body();
        let item_value = body.deserialize::<zvariant::Value>().unwrap();
        let item_label: String = item_value.downcast().unwrap();

        assert!(item_object_path.starts_with(collection_object_path.as_str()));
        assert_eq!(prompt.as_str(), "/");
        assert_eq!(item_label.as_str(), "test-item-label");

        run_server_handle.abort();
        assert!(run_server_handle.await.unwrap_err().is_cancelled());

        Ok(())
    }

    #[tokio::test]
    async fn test_search_items() -> Result<(), error::Error> {
        let (dbus_name, run_server_handle) = run_service_server().await;
        let session_path = open_plain_session(dbus_name.as_str()).await?;
        let collection_object_path =
            create_collection(dbus_name.as_str(), "test-collection-label").await?;

        let connection = zbus::Connection::session().await?;
        let item_attributes = collections::HashMap::from([
            ("key-one".to_string(), "value-one".to_string()),
            ("key-two".to_string(), "value-two".to_string()),
        ]);
        let item_properties = item::ItemReadWriteProperties {
            attributes: item_attributes.clone(),
            label: "test-item-label".to_owned(),
        };

        let secret = secret::Secret {
            session: session_path,
            value: "a-very-important-secret".into(),
            parameters: Vec::new(),
            content_type: "text/plain; charset=utf8".to_string(),
        };
        let reply = connection
            .call_method(
                Some(dbus_name.as_str()),
                collection_object_path.as_str(),
                Some("org.freedesktop.Secret.Collection"),
                "CreateItem",
                &(item_properties, secret, false),
            )
            .await
            .unwrap();

        let body = reply.body();
        let (item_object_path, _): (zvariant::ObjectPath<'_>, zvariant::ObjectPath<'_>) =
            body.deserialize().unwrap();

        let reply = connection
            .call_method(
                Some(dbus_name.as_str()),
                collection_object_path.as_str(),
                Some("org.freedesktop.Secret.Collection"),
                "SearchItems",
                &(item_attributes),
            )
            .await
            .unwrap();

        let body = reply.body();
        let found_items: Vec<zvariant::ObjectPath<'_>> = body.deserialize().unwrap();

        assert_eq!(found_items.len(), 1);
        assert_eq!(found_items.get(0).unwrap(), &item_object_path);

        run_server_handle.abort();
        assert!(run_server_handle.await.unwrap_err().is_cancelled());

        Ok(())
    }
}
