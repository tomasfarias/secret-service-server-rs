use std::collections;
use std::str;

use crate::collection;
use crate::error;
use crate::item;
use crate::secret;
use crate::session;

#[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct Service {
    aliases: collections::HashMap<String, String>,
    pub collections: collections::HashMap<String, collection::Collection>,
    pub sessions: collections::HashMap<String, session::Session>,
    pub object_path: zvariant::OwnedObjectPath,
}

impl Service {
    pub fn new() -> Self {
        let object_path = zvariant::OwnedObjectPath::try_from("/org/freedesktop/secrets")
            .expect("hard-coded object path value shouldn't fail conversion");

        Self {
            collections: collections::HashMap::new(),
            aliases: collections::HashMap::new(),
            sessions: collections::HashMap::new(),
            object_path,
        }
    }

    pub fn insert_session(&mut self, session: session::Session) -> &session::Session {
        let key = session.object_path.as_ref().to_string();

        self.sessions.insert(key.clone(), session);
        self.sessions
            .get(&key)
            .expect("key must exist as it was just inserted")
    }

    pub fn create_collection_internal(
        &mut self,
        collection: collection::Collection,
    ) -> Result<&collection::Collection, error::Error> {
        let key = collection.object_path.as_ref().to_string();

        self.collections.insert(key.clone(), collection);
        let (inserted_collection_path, inserted_collection_alias) = {
            let inserted_collection = self
                .collections
                .get(&key)
                .expect("just inserted value should be present");

            (
                inserted_collection.object_path.clone(),
                inserted_collection.alias.clone(),
            )
        };

        if let Some(alias) = inserted_collection_alias {
            self.try_insert_collection_alias(&inserted_collection_path.as_ref(), &alias)?;
        }

        log::info!(
            "Created collection at '{}'",
            inserted_collection_path.as_str()
        );

        Ok(self
            .collections
            .get(&key)
            .expect("key must exist as it was just inserted"))
    }

    pub fn try_insert_collection_alias(
        &mut self,
        object_path: &zvariant::ObjectPath<'_>,
        alias: &str,
    ) -> Result<(), error::Error> {
        let key = alias.to_owned();
        let collection_object_path = object_path.as_ref().to_string();

        match self.aliases.entry(key) {
            collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(collection_object_path);
                Ok(())
            }
            collections::hash_map::Entry::Occupied(entry) => {
                Err(error::Error::CollectionAliasExists(entry.key().to_owned()))
            }
        }
    }

    pub fn try_update_collection_alias(
        &mut self,
        object_path: &zvariant::ObjectPath<'_>,
        alias: &str,
    ) -> Result<String, error::Error> {
        let key = alias.to_owned();
        let collection_object_path = object_path.as_ref().to_string();

        let collection = self
            .collections
            .get_mut(&collection_object_path)
            .ok_or(error::Error::NoSuchObject(collection_object_path.clone()))?;
        collection.alias = Some(alias.to_owned());

        match self.aliases.entry(key) {
            collections::hash_map::Entry::Vacant(entry) => {
                let inserted_entry = entry.insert(collection_object_path);
                Ok(inserted_entry.to_string())
            }
            collections::hash_map::Entry::Occupied(mut entry) => {
                let old_entry = entry.insert(collection_object_path);
                Ok(old_entry)
            }
        }
    }

    pub fn try_lock_collection(
        &mut self,
        object_path: &zvariant::ObjectPath<'_>,
    ) -> Result<(), error::Error> {
        let collection = self
            .get_mut_collection_by_path(object_path)
            .ok_or(error::Error::NoSuchObject(object_path.as_str().to_owned()))?;

        if !collection.locked {
            collection.locked = true;
        }
        Ok(())
    }

    pub fn try_unlock_collection(
        &mut self,
        object_path: &zvariant::ObjectPath<'_>,
    ) -> Result<(), error::Error> {
        let collection = self
            .get_mut_collection_by_path(object_path)
            .ok_or(error::Error::NoSuchObject(object_path.as_str().to_owned()))?;

        if collection.locked {
            collection.locked = false;
        }
        Ok(())
    }

    pub fn get_mut_collection_by_path(
        &mut self,
        object_path: &zvariant::ObjectPath<'_>,
    ) -> Option<&mut collection::Collection> {
        let collection_object_path = object_path.as_ref().to_string();
        self.collections.get_mut(&collection_object_path)
    }

    pub fn try_lock_item(
        &mut self,
        object_path: &zvariant::ObjectPath<'_>,
    ) -> Result<(), error::Error> {
        let item = self
            .get_mut_item_by_path(object_path)
            .ok_or(error::Error::NoSuchObject(object_path.as_str().to_owned()))?;

        if !item.locked {
            item.locked = true;
        }
        Ok(())
    }

    pub fn try_unlock_item(
        &mut self,
        object_path: &zvariant::ObjectPath<'_>,
    ) -> Result<(), error::Error> {
        let item = self
            .get_mut_item_by_path(object_path)
            .ok_or(error::Error::NoSuchObject(object_path.as_str().to_owned()))?;

        if item.locked {
            item.locked = false;
        }
        Ok(())
    }

    pub fn get_mut_item_by_path(
        &mut self,
        object_path: &zvariant::ObjectPath<'_>,
    ) -> Option<&mut item::Item> {
        let item_object_path = object_path.as_ref().to_string();

        for (_, collection) in self.collections.iter_mut() {
            if let Some(item) = collection.items.get_mut(&item_object_path) {
                return Some(item);
            }
        }
        None
    }

    pub fn remove_collection_alias(&mut self, alias: &str) -> Option<String> {
        self.aliases.remove(alias)
    }

    pub fn collection_exists(&self, object_path: &zvariant::ObjectPath<'_>) -> bool {
        self.collections.contains_key(object_path.as_str())
    }

    pub fn create_default_collection(&mut self) -> Result<zvariant::ObjectPath<'_>, error::Error> {
        let new_collection = collection::Collection::new_default(self);
        let added_collection = self.create_collection_internal(new_collection)?;

        Ok(added_collection.object_path.as_ref())
    }
}

#[zbus::interface(name = "org.freedesktop.Secret.Service")]
impl Service {
    /// CreateCollection method
    async fn create_collection(
        &mut self,
        properties: collection::CollectionReadWriteProperties,
        alias: &str,
        #[zbus(signal_emitter)] emitter: zbus::object_server::SignalEmitter<'_>,
    ) -> Result<(zvariant::ObjectPath<'_>, zvariant::ObjectPath<'_>), error::Error> {
        if !alias.is_empty() {
            if let Some(collection_key) = self.aliases.get(alias) {
                Ok((
                    self.collections
                        .get(collection_key)
                        .expect("alias is added with each collection")
                        .object_path
                        .as_ref(),
                    zvariant::ObjectPath::try_from("/").expect("well-known path should not fail"),
                ))
            } else {
                let collection_id = uuid::Uuid::new_v4();
                let new_collection = collection::Collection::new(
                    &collection_id,
                    &properties.label,
                    Some(alias),
                    self,
                );
                let added_collection = self.create_collection_internal(new_collection)?;

                emitter.collection_created().await?;

                Ok((
                    added_collection.object_path.as_ref(),
                    zvariant::ObjectPath::try_from("/").expect("well-known path should not fail"),
                ))
            }
        } else {
            let collection_id = uuid::Uuid::new_v4();
            let new_collection =
                collection::Collection::new(&collection_id, &properties.label, None, self);
            let added_collection = self.create_collection_internal(new_collection)?;

            emitter.collection_created().await?;

            Ok((
                added_collection.object_path.as_ref(),
                zvariant::ObjectPath::try_from("/").expect("well-known path should not fail"),
            ))
        }
    }

    /// GetSecrets method
    async fn get_secrets(
        &self,
        items: Vec<zvariant::ObjectPath<'_>>,
        session: zvariant::ObjectPath<'_>,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
    ) -> Result<collections::HashMap<zvariant::OwnedObjectPath, secret::Secret>, error::Error> {
        let mut secrets_map = collections::HashMap::new();

        for collection in self.collections.values() {
            if collection.locked {
                continue;
            }

            for item in items.iter() {
                let item_str = item.as_str();
                if let Some(found_item) = collection.items.get(item_str) {
                    if found_item.locked {
                        continue;
                    }

                    let session_path = session.clone();
                    let secret = found_item.get_secret(session_path, object_server).await?;

                    secrets_map.insert(
                        zvariant::OwnedObjectPath::try_from(item_str)
                            .expect("existing path should not fail"),
                        secret,
                    );
                }
            }
        }

        Ok(secrets_map)
    }

    /// Lock method
    async fn lock(
        &mut self,
        objects: Vec<zvariant::ObjectPath<'_>>,
    ) -> (Vec<zvariant::OwnedObjectPath>, zvariant::OwnedObjectPath) {
        let mut locked = Vec::new();

        for object in objects.iter() {
            if let Ok(()) = self.try_lock_collection(object) {
                locked.push(
                    zvariant::OwnedObjectPath::try_from(object.as_str())
                        .expect("existing path should not fail"),
                );
                continue;
            }

            if let Ok(()) = self.try_lock_item(object) {
                locked.push(
                    zvariant::OwnedObjectPath::try_from(object.as_str())
                        .expect("existing path should not fail"),
                );
            }
        }

        (
            locked,
            zvariant::OwnedObjectPath::try_from("/").expect("well-known path should not fail"),
        )
    }

    /// OpenSession method
    async fn open_session(
        &mut self,
        algorithm: &str,
        input: zvariant::Value<'_>,
    ) -> Result<(zvariant::OwnedValue, zvariant::ObjectPath<'_>), error::Error> {
        let session_id = uuid::Uuid::new_v4();
        let public_key = zvariant::Str::try_from(input).unwrap();

        match algorithm {
            "plain" => {
                let session = session::Session::new_with_id(&session_id).plain();
                let added_session = self.insert_session(session);

                Ok((
                    zvariant::Value::new("").try_to_owned().unwrap(),
                    added_session.object_path.as_ref(),
                ))
            }
            "dh-ietf1024-sha256-aes128-cbc-pkcs7" => {
                let (session, server_public_key) = session::Session::new_with_id(&session_id)
                    .dh(public_key.as_str().as_bytes().try_into().unwrap());
                let added_session = self.insert_session(session);

                Ok((
                    zvariant::Value::new(str::from_utf8(&server_public_key).unwrap())
                        .try_to_owned()
                        .unwrap(),
                    added_session.object_path.as_ref(),
                ))
            }
            algorithm => Err(error::Error::AlgorithmUnsupported(algorithm.to_owned())),
        }
    }

    /// ReadAlias method
    fn read_alias(&self, name: &str) -> zvariant::OwnedObjectPath {
        if let Some(matching_collection) = self.aliases.get(name) {
            zvariant::OwnedObjectPath::try_from(matching_collection.as_str())
                .expect("existing path should not fail")
        } else {
            zvariant::OwnedObjectPath::try_from("/").expect("well-known path should not fail")
        }
    }

    /// SearchItems method
    fn search_items(
        &self,
        attributes: collections::HashMap<String, String>,
    ) -> (
        Vec<zvariant::OwnedObjectPath>,
        Vec<zvariant::OwnedObjectPath>,
    ) {
        let mut unlocked = Vec::new();
        let mut locked = Vec::new();

        for (key, value) in attributes.into_iter() {
            let attributes_key = (key, value);
            for collection in self.collections.values() {
                if let Some(matching_paths) = collection.lookup_attributes.get(&attributes_key) {
                    for path in matching_paths {
                        let item = collection
                            .items
                            .get(path.as_str())
                            .expect("item must exist");
                        if !item.locked && !collection.locked {
                            unlocked.push(
                                zvariant::OwnedObjectPath::try_from(path.as_str())
                                    .expect("existing path should not fail"),
                            )
                        } else {
                            locked.push(
                                zvariant::OwnedObjectPath::try_from(path.as_str())
                                    .expect("existing path should not fail"),
                            )
                        }
                    }
                }
            }
        }

        (unlocked, locked)
    }

    /// SetAlias method
    fn set_alias(
        &mut self,
        name: &str,
        collection: zvariant::ObjectPath<'_>,
    ) -> Result<(), error::Error> {
        if !self.collection_exists(&collection) {
            Err(error::Error::NoSuchObject(collection.as_str().to_owned()))
        } else {
            if collection.as_str() == "/" {
                self.remove_collection_alias(name);
            } else {
                self.try_update_collection_alias(&collection, name)?;
            }

            Ok(())
        }
    }

    /// Unlock method
    fn unlock(
        &mut self,
        objects: Vec<zvariant::ObjectPath<'_>>,
    ) -> (Vec<zvariant::OwnedObjectPath>, zvariant::OwnedObjectPath) {
        let mut unlocked = Vec::new();

        for object in objects.iter() {
            if let Ok(()) = self.try_unlock_collection(object) {
                unlocked.push(
                    zvariant::OwnedObjectPath::try_from(object.as_str())
                        .expect("existing path should not fail"),
                );
                continue;
            }

            if let Ok(()) = self.try_unlock_item(object) {
                unlocked.push(
                    zvariant::OwnedObjectPath::try_from(object.as_str())
                        .expect("existing path should not fail"),
                );
            }
        }

        (
            unlocked,
            zvariant::OwnedObjectPath::try_from("/").expect("well-known path should not fail"),
        )
    }

    /// CollectionChanged signal
    #[zbus(signal)]
    pub async fn collection_changed(
        emitter: &zbus::object_server::SignalEmitter<'_>,
    ) -> zbus::Result<()>;

    /// CollectionCreated signal
    #[zbus(signal)]
    async fn collection_created(
        emitter: &zbus::object_server::SignalEmitter<'_>,
    ) -> zbus::Result<()>;

    /// CollectionDeleted signal
    #[zbus(signal)]
    pub async fn collection_deleted(
        emitter: &zbus::object_server::SignalEmitter<'_>,
    ) -> zbus::Result<()>;

    /// Collections property
    #[zbus(property)]
    fn collections(&self) -> Vec<zvariant::OwnedObjectPath> {
        self.collections
            .keys()
            .map(|key| zvariant::OwnedObjectPath::try_from(key.as_str()).unwrap())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[tokio::test]
    async fn test_create_collection() -> Result<(), error::Error> {
        let (dbus_name, run_server_handle) = run_service_server().await;

        let connection = zbus::Connection::session().await?;
        let collection_properties = collections::HashMap::from([(
            "org.freedesktop.Secret.Collection.Label",
            zvariant::Value::new("test-label"),
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
        let (collection_object_path, prompt): (zvariant::ObjectPath<'_>, zvariant::ObjectPath<'_>) =
            body.deserialize().unwrap();

        run_server_handle.abort();
        assert!(run_server_handle.await.unwrap_err().is_cancelled());

        assert!(collection_object_path
            .as_str()
            .starts_with("/org/freedesktop/secrets/collection/"));
        assert_eq!(prompt.as_str(), "/");

        Ok(())
    }

    #[tokio::test]
    async fn test_create_collection_returns_existing_object_path() -> Result<(), error::Error> {
        let (dbus_name, run_server_handle) = run_service_server().await;

        let connection = zbus::Connection::session().await?;
        let collection_properties = collections::HashMap::from([(
            "org.freedesktop.Secret.Collection.Label",
            zvariant::Value::new("test-label"),
        )]);
        let connection_alias = "my-collection".to_owned();

        let reply = connection
            .call_method(
                Some(dbus_name.as_str()),
                "/org/freedesktop/secrets",
                Some("org.freedesktop.Secret.Service"),
                "CreateCollection",
                &(&collection_properties, &connection_alias),
            )
            .await
            .unwrap();

        let body = reply.body();
        let (collection_object_path, prompt): (zvariant::ObjectPath<'_>, zvariant::ObjectPath<'_>) =
            body.deserialize().unwrap();

        assert!(collection_object_path
            .as_str()
            .starts_with("/org/freedesktop/secrets/collection/"));
        assert_eq!(prompt.as_str(), "/");

        let reply = connection
            .call_method(
                Some(dbus_name.as_str()),
                "/org/freedesktop/secrets",
                Some("org.freedesktop.Secret.Service"),
                "CreateCollection",
                &(&collection_properties, &connection_alias),
            )
            .await
            .unwrap();

        let body = reply.body();
        let (new_collection_object_path, new_prompt): (
            zvariant::ObjectPath<'_>,
            zvariant::ObjectPath<'_>,
        ) = body.deserialize().unwrap();

        run_server_handle.abort();
        assert!(run_server_handle.await.unwrap_err().is_cancelled());

        assert_eq!(new_collection_object_path, collection_object_path);
        assert_eq!(new_prompt, prompt);

        Ok(())
    }

    #[tokio::test]
    async fn test_collections_property() -> Result<(), error::Error> {
        let (dbus_name, run_server_handle) = run_service_server().await;

        let connection = zbus::Connection::session().await?;
        let collection_properties = collections::HashMap::from([(
            "org.freedesktop.Secret.Collection.Label",
            zvariant::Value::new("test-label"),
        )]);

        let reply = connection
            .call_method(
                Some(dbus_name.as_str()),
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

        let reply = connection
            .call_method(
                Some(dbus_name.as_str()),
                "/org/freedesktop/secrets",
                Some("org.freedesktop.DBus.Properties"),
                "Get",
                &(
                    "org.freedesktop.Secret.Service".to_string(),
                    "Collections".to_string(),
                ),
            )
            .await
            .unwrap();

        let body = reply.body();
        let collections_value = body.deserialize::<zvariant::Value>().unwrap();
        let collections: Vec<zvariant::ObjectPath<'_>> = collections_value.downcast().unwrap();

        run_server_handle.abort();
        assert!(run_server_handle.await.unwrap_err().is_cancelled());

        // Includes default collection besides the one we have created.
        assert_eq!(collections.len(), 2);
        assert!(collections.contains(&collection_object_path));
        let default_collection_path =
            zvariant::ObjectPath::try_from("/org/freedesktop/secrets/aliases/default").unwrap();
        assert!(collections.contains(&default_collection_path));

        Ok(())
    }

    #[tokio::test]
    async fn test_read_alias() -> Result<(), error::Error> {
        let (dbus_name, run_server_handle) = run_service_server().await;

        let connection = zbus::Connection::session().await?;
        let collection_properties = collections::HashMap::from([(
            "org.freedesktop.Secret.Collection.Label",
            zvariant::Value::new("test-label"),
        )]);
        let collection_alias = "collection-alias".to_owned();

        let reply = connection
            .call_method(
                Some(dbus_name.as_str()),
                "/org/freedesktop/secrets",
                Some("org.freedesktop.Secret.Service"),
                "CreateCollection",
                &(collection_properties, &collection_alias),
            )
            .await
            .unwrap();

        let body = reply.body();
        let (collection_object_path, _): (zvariant::ObjectPath<'_>, zvariant::ObjectPath<'_>) =
            body.deserialize().unwrap();

        assert_ne!(
            collection_object_path,
            zvariant::ObjectPath::try_from("/").unwrap()
        );

        let reply = connection
            .call_method(
                Some(dbus_name.as_str()),
                "/org/freedesktop/secrets",
                Some("org.freedesktop.Secret.Service"),
                "ReadAlias",
                &(&collection_alias),
            )
            .await
            .unwrap();

        let body = reply.body();
        let new_collection_object_path: zvariant::ObjectPath<'_> = body.deserialize().unwrap();

        run_server_handle.abort();
        assert!(run_server_handle.await.unwrap_err().is_cancelled());

        assert_eq!(new_collection_object_path, collection_object_path);

        Ok(())
    }

    #[tokio::test]
    async fn test_set_alias_updates_collection_alias() -> Result<(), error::Error> {
        let (dbus_name, run_server_handle) = run_service_server().await;

        let connection = zbus::Connection::session().await?;
        let collection_properties = collections::HashMap::from([(
            "org.freedesktop.Secret.Collection.Label",
            zvariant::Value::new("test-label"),
        )]);

        let reply = connection
            .call_method(
                Some(dbus_name.as_str()),
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

        let collection_alias = "new-alias".to_owned();
        let reply = connection
            .call_method(
                Some(dbus_name.as_str()),
                "/org/freedesktop/secrets",
                Some("org.freedesktop.Secret.Service"),
                "SetAlias",
                &(&collection_alias, &collection_object_path),
            )
            .await
            .unwrap();

        let body = reply.body();
        let _: () = body.deserialize().unwrap();

        let reply = connection
            .call_method(
                Some(dbus_name.as_str()),
                "/org/freedesktop/secrets",
                Some("org.freedesktop.Secret.Service"),
                "ReadAlias",
                &(&collection_alias),
            )
            .await
            .unwrap();

        let body = reply.body();
        let new_collection_object_path: zvariant::ObjectPath<'_> = body.deserialize().unwrap();

        run_server_handle.abort();
        assert!(run_server_handle.await.unwrap_err().is_cancelled());

        assert_eq!(new_collection_object_path, collection_object_path);

        Ok(())
    }
}
