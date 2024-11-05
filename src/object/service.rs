use std::collections;
use std::str;

use futures::{stream, StreamExt};

use crate::error;
use crate::object::collection;
use crate::object::collection::CollectionSignals;
use crate::object::item;
use crate::object::session;
use crate::object::{SecretServiceChildObject, SecretServiceDbusObject, SecretServiceParentObject};

use crate::secret;

#[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct Service {
    aliases: collections::HashMap<String, zvariant::OwnedObjectPath>,
    pub collections: collections::HashSet<zvariant::OwnedObjectPath>,
}

impl Service {
    pub fn new() -> Self {
        Self {
            aliases: collections::HashMap::new(),
            collections: collections::HashSet::new(),
        }
    }
}

impl SecretServiceDbusObject for Service {
    fn get_object_path(&self) -> zvariant::OwnedObjectPath {
        zvariant::ObjectPath::from_str_unchecked("/org/freedesktop/secrets").into()
    }
}

impl SecretServiceParentObject for Service {
    fn get_children(&self) -> &collections::HashSet<zvariant::OwnedObjectPath> {
        &self.collections
    }

    fn get_mut_children(&mut self) -> &mut collections::HashSet<zvariant::OwnedObjectPath> {
        &mut self.collections
    }
}

#[zbus::interface(name = "org.freedesktop.Secret.Service")]
impl Service {
    /// CreateCollection method
    pub async fn create_collection(
        &mut self,
        properties: collection::CollectionReadWriteProperties,
        alias: &str,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
        #[zbus(signal_emitter)] emitter: zbus::object_server::SignalEmitter<'_>,
    ) -> Result<(zvariant::OwnedObjectPath, zvariant::ObjectPath<'_>), error::Error> {
        let collection_alias = if !alias.is_empty() {
            if let Some(collection_path) = self.aliases.get(alias) {
                return Ok((
                    collection_path.clone(),
                    zvariant::ObjectPath::from_str_unchecked("/"),
                ));
            }

            Some(alias)
        } else {
            None
        };

        let collection_id = uuid::Uuid::new_v4();
        let new_collection = match collection_alias {
            Some("default") => collection::Collection::new_default(self),
            Some(_) | None => collection::Collection::new(
                collection_id,
                &properties.label,
                collection_alias,
                self,
            ),
        };

        let (collection_path, _) = new_collection.serve_at(object_server).await?;

        emitter.collection_created().await?;

        log::info!("Created new collection on '{collection_path}'");
        self.collections.insert(collection_path.clone());
        if let Some(collection_alias) = collection_alias {
            self.aliases
                .insert(collection_alias.to_string(), collection_path.clone());
        };

        Ok((
            collection_path,
            zvariant::ObjectPath::from_str_unchecked("/"),
        ))
    }

    /// GetSecrets method
    async fn get_secrets(
        &self,
        items: Vec<zvariant::OwnedObjectPath>,
        session: zvariant::ObjectPath<'_>,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
    ) -> Result<collections::HashMap<zvariant::OwnedObjectPath, secret::Secret>, error::Error> {
        let session_interface =
            session::Session::get_interface_from_object_path(&session, object_server).await?;
        let session = *(session_interface.get().await);

        let mut tasks = stream::FuturesUnordered::new();

        for item_path in items {
            tasks.push(async move {
                let item_interface =
                    match item::Item::get_interface_from_object_path(&item_path, object_server)
                        .await
                    {
                        Ok(interface) => interface,
                        Err(_) => {
                            return None;
                        }
                    };

                let item = item_interface.get().await;

                if item.locked {
                    return None;
                }

                let collection_interface = match item.get_parent_interface(object_server).await {
                    Ok(interface) => interface,
                    Err(_) => {
                        return None;
                    }
                };
                let collection = collection_interface.get().await;

                if collection.locked {
                    return None;
                }

                let secret = item.get_secret_with_session(&session);
                Some((item.get_object_path(), secret))
            });
        }

        let mut secrets_map = collections::HashMap::new();

        while let Some(res) = tasks.next().await {
            if let Some((object_path, secret)) = res {
                secrets_map.insert(object_path, secret);
            }
        }

        Ok(secrets_map)
    }

    /// Lock method
    async fn lock(
        &mut self,
        objects: Vec<zvariant::ObjectPath<'_>>,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
        #[zbus(signal_emitter)] emitter: zbus::object_server::SignalEmitter<'_>,
    ) -> Result<(Vec<zvariant::OwnedObjectPath>, zvariant::ObjectPath<'_>), error::Error> {
        let mut locked = Vec::new();

        for object in objects.iter() {
            if let Ok(collection_interface) =
                collection::Collection::get_interface_from_object_path(object, object_server).await
            {
                let mut collection = collection_interface.get_mut().await;
                if !collection.locked {
                    collection.locked = true;

                    emitter.collection_changed().await?;

                    locked.push(collection.get_object_path());
                }
                continue;
            }

            if let Ok(item_interface) =
                item::Item::get_interface_from_object_path(object, object_server).await
            {
                let mut item = item_interface.get_mut().await;
                if !item.locked {
                    item.locked = true;

                    emitter.item_changed().await?;

                    locked.push(item.get_object_path());
                }
                continue;
            }
        }

        Ok((locked, zvariant::ObjectPath::from_str_unchecked("/")))
    }

    /// Lock method
    async fn unlock(
        &mut self,
        objects: Vec<zvariant::ObjectPath<'_>>,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
        #[zbus(signal_emitter)] emitter: zbus::object_server::SignalEmitter<'_>,
    ) -> Result<(Vec<zvariant::OwnedObjectPath>, zvariant::ObjectPath<'_>), error::Error> {
        let mut unlocked = Vec::new();

        for object in objects.iter() {
            if let Ok(collection_interface) =
                collection::Collection::get_interface_from_object_path(object, object_server).await
            {
                let mut collection = collection_interface.get_mut().await;
                if collection.locked {
                    collection.locked = false;

                    emitter.collection_changed().await?;

                    unlocked.push(collection.get_object_path());
                }
                continue;
            }

            if let Ok(item_interface) =
                item::Item::get_interface_from_object_path(object, object_server).await
            {
                let mut item = item_interface.get_mut().await;
                if item.locked {
                    item.locked = false;

                    emitter.item_changed().await?;

                    unlocked.push(item.get_object_path());
                }
                continue;
            }
        }

        Ok((unlocked, zvariant::ObjectPath::from_str_unchecked("/")))
    }

    /// OpenSession method
    async fn open_session(
        &self,
        algorithm: &str,
        input: zvariant::Value<'_>,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
    ) -> Result<(zvariant::Value<'_>, zvariant::ObjectPath<'_>), error::Error> {
        let (new_session, return_value) = match algorithm {
            "plain" => {
                let public_key_bytes: Vec<u8> = input.try_into()?;

                if let Ok(public_key) = str::from_utf8(&public_key_bytes) {
                    if !public_key.is_empty() {
                        return Err(error::Error::InvalidArgs(
                            "OpenSession".to_owned(),
                            "Expected input to be '\"\"' when requesting a 'plain' session."
                                .to_owned(),
                        ));
                    }
                }
                let session = session::Session::new_plain();

                (session, zvariant::Value::from(""))
            }
            "dh-ietf1024-sha256-aes128-cbc-pkcs7" => {
                let public_key_bytes: Vec<u8> = input.try_into()?;
                let public_key = public_key_bytes.try_into().map_err(|_| {
                    error::Error::InvalidArgs(
                        "OpenSession".to_owned(),
                        "Invalid key length".to_owned(),
                    )
                })?;
                let (session, server_public_key) = session::Session::new_dh(public_key)?;
                let mut public_key_vec: Vec<u8> = Vec::with_capacity(server_public_key.len());
                public_key_vec.extend_from_slice(&server_public_key);

                let v: zvariant::Value = server_public_key.to_vec().into();

                (session, v)
            }
            algorithm => {
                return Err(error::Error::AlgorithmUnsupported(algorithm.to_owned()));
            }
        };
        let (session_path, _) = new_session.serve_at(object_server).await?;

        log::info!("Opened new session on '{session_path}'");

        Ok((return_value, session_path.into()))
    }

    /// ReadAlias method
    fn read_alias(&self, name: &str) -> zvariant::ObjectPath<'_> {
        if let Some(matching_collection) = self.aliases.get(name) {
            zvariant::ObjectPath::try_from(matching_collection.as_str())
                .expect("existing path should not fail")
        } else {
            zvariant::ObjectPath::from_str_unchecked("/")
        }
    }

    /// SetAlias method
    async fn set_alias(
        &mut self,
        name: &str,
        collection: zvariant::ObjectPath<'_>,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
    ) -> Result<(), error::Error> {
        match collection.as_str() {
            "/" => {
                if let Some(collection_path) = self.aliases.get(name) {
                    let collection_interface =
                        collection::Collection::get_interface_from_object_path(
                            collection_path,
                            object_server,
                        )
                        .await?;

                    let mut collection = collection_interface.get_mut().await;
                    collection.alias = None;
                    self.aliases.remove(name);

                    Ok(())
                } else {
                    Err(error::Error::NoSuchObject(name.to_owned()))
                }
            }
            _ => {
                let collection_interface = collection::Collection::get_interface_from_object_path(
                    &collection,
                    object_server,
                )
                .await?;
                let mut collection = collection_interface.get_mut().await;
                collection.alias = Some(name.to_string());
                self.aliases.remove(name);
                self.aliases
                    .insert(name.to_string(), collection.get_object_path());

                Ok(())
            }
        }
    }

    /// SearchItems method
    async fn search_items(
        &self,
        attributes: collections::HashMap<String, String>,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
    ) -> (
        Vec<zvariant::OwnedObjectPath>,
        Vec<zvariant::OwnedObjectPath>,
    ) {
        let mut unlocked = Vec::new();
        let mut locked = Vec::new();

        for collection_path in self.collections.iter() {
            if let Ok(collection_interface) =
                collection::Collection::get_interface_from_object_path(
                    &collection_path.as_ref(),
                    object_server,
                )
                .await
            {
                let collection = collection_interface.get().await;

                for item_path in collection.search_items(attributes.clone()).iter() {
                    if let Ok(item_interface) = item::Item::get_interface_from_object_path(
                        &item_path.as_ref(),
                        object_server,
                    )
                    .await
                    {
                        let item = item_interface.get().await;
                        if item.locked {
                            locked.push(item.get_object_path());
                        } else {
                            unlocked.push(item.get_object_path());
                        }
                    }
                }
            }
        }

        (unlocked, locked)
    }

    /// Collections property
    #[zbus(property)]
    fn collections(&self) -> Vec<zvariant::ObjectPath<'_>> {
        self.get_children()
            .iter()
            .map(|path| path.as_ref())
            .collect()
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
        let plain_key: Vec<u8> = Vec::new();

        let reply = connection
            .call_method(
                Some(dbus_name),
                "/org/freedesktop/secrets",
                Some("org.freedesktop.Secret.Service"),
                "OpenSession",
                &("plain", zvariant::Value::from(plain_key)),
            )
            .await
            .unwrap();

        let body = reply.body();
        let (_, session_path): (zvariant::Value, zvariant::ObjectPath<'_>) =
            body.deserialize().unwrap();

        Ok(session_path.into())
    }

    #[tokio::test]
    async fn test_create_collection() -> Result<(), error::Error> {
        let (dbus_name, run_server_handle) = run_service_server().await;

        let connection = zbus::Connection::session().await?;
        let collection_properties = collection::CollectionReadWriteProperties {
            label: "test-label".to_string(),
        };

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
        let (collection_object_path, prompt): (zvariant::ObjectPath<'_>, zvariant::ObjectPath<'_>) =
            body.deserialize().unwrap();

        let reply = connection
            .call_method(
                Some(dbus_name.as_str()),
                &collection_object_path,
                Some("org.freedesktop.DBus.Properties"),
                "Get",
                &(
                    "org.freedesktop.Secret.Collection".to_string(),
                    "Label".to_string(),
                ),
            )
            .await
            .unwrap();

        let body = reply.body();
        let collection_value = body.deserialize::<zvariant::Value>().unwrap();
        let collection_label: String = collection_value.downcast().unwrap();

        run_server_handle.abort();
        assert!(run_server_handle.await.unwrap_err().is_cancelled());

        assert!(collection_object_path
            .as_str()
            .starts_with("/org/freedesktop/secrets/collection/"));
        assert_eq!(prompt.as_str(), "/");
        assert_eq!(collection_label.as_str(), "test-label");

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
            zvariant::ObjectPath::from_str_unchecked("/org/freedesktop/secrets/aliases/default");
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
            zvariant::ObjectPath::from_str_unchecked("/")
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

    #[tokio::test]
    async fn test_open_session_plain() -> Result<(), error::Error> {
        let (dbus_name, run_server_handle) = run_service_server().await;

        let connection = zbus::Connection::session().await?;
        let plain_key: Vec<u8> = Vec::new();

        let reply = connection
            .call_method(
                Some(dbus_name),
                "/org/freedesktop/secrets",
                Some("org.freedesktop.Secret.Service"),
                "OpenSession",
                &("plain", zvariant::Value::from(plain_key)),
            )
            .await
            .unwrap();

        let body = reply.body();
        let (algorithm_output, session_path): (zvariant::Value, zvariant::ObjectPath<'_>) =
            body.deserialize().unwrap();

        run_server_handle.abort();
        assert!(run_server_handle.await.unwrap_err().is_cancelled());

        assert_eq!(algorithm_output.to_string(), "\"\"".to_owned());
        assert!(session_path.starts_with("/org/freedesktop/secrets/session/"));

        Ok(())
    }

    #[tokio::test]
    async fn test_open_session_dh() -> Result<(), error::Error> {
        let (dbus_name, run_server_handle) = run_service_server().await;

        let connection = zbus::Connection::session().await?;

        let secret = x25519_dalek::EphemeralSecret::random();
        let public_key = x25519_dalek::PublicKey::from(&secret);

        let reply = connection
            .call_method(
                Some(dbus_name),
                "/org/freedesktop/secrets",
                Some("org.freedesktop.Secret.Service"),
                "OpenSession",
                &(
                    "dh-ietf1024-sha256-aes128-cbc-pkcs7",
                    zvariant::Value::from(public_key.as_bytes().to_vec()),
                ),
            )
            .await
            .unwrap();

        let body = reply.body();
        let (algorithm_output, session_path): (zvariant::Value, zvariant::ObjectPath<'_>) =
            body.deserialize().unwrap();
        let server_public_key_bytes: Vec<u8> = algorithm_output.try_into()?;
        let server_public_key: [u8; 32] = server_public_key_bytes.try_into().unwrap();

        let shared_secret =
            secret.diffie_hellman(&x25519_dalek::PublicKey::from(server_public_key));
        let shared_secret_bytes = shared_secret.to_bytes();

        let mut shared_secret_padded = vec![0u8; 128 - shared_secret_bytes.len()];
        shared_secret_padded.extend_from_slice(&shared_secret_bytes);

        let info = [];
        let salt = None;

        let (_, hk) = hkdf::Hkdf::<sha2::Sha256>::extract(salt, &shared_secret_padded);
        let mut key = [0; 16];
        hk.expand(&info, &mut key).unwrap();

        run_server_handle.abort();
        assert!(run_server_handle.await.unwrap_err().is_cancelled());

        assert!(session_path.starts_with("/org/freedesktop/secrets/session/"));

        Ok(())
    }

    #[tokio::test]
    async fn test_search_items() -> Result<(), error::Error> {
        let (dbus_name, run_server_handle) = run_service_server().await;
        let session_path = open_plain_session(dbus_name.as_str()).await?;
        let collection_one_object_path =
            create_collection(dbus_name.as_str(), "test-collection-1").await?;
        let collection_two_object_path =
            create_collection(dbus_name.as_str(), "test-collection-2").await?;

        let connection = zbus::Connection::session().await?;
        let item_attributes =
            collections::HashMap::from([("key-one".to_string(), "value-one".to_string())]);

        let mut created_items: Vec<zvariant::OwnedObjectPath> = Vec::new();
        for collection_object_path in vec![collection_one_object_path, collection_two_object_path] {
            let item_properties = item::ItemReadWriteProperties {
                attributes: item_attributes.clone(),
                label: "test-item-label".to_owned(),
            };

            let secret = secret::Secret {
                session: session_path.clone(),
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

            created_items.push(item_object_path.into());
        }

        let reply = connection
            .call_method(
                Some(dbus_name.as_str()),
                "/org/freedesktop/secrets",
                Some("org.freedesktop.Secret.Service"),
                "SearchItems",
                &(item_attributes),
            )
            .await
            .unwrap();

        let body = reply.body();
        let (unlocked, locked): (
            Vec<zvariant::OwnedObjectPath>,
            Vec<zvariant::OwnedObjectPath>,
        ) = body.deserialize().unwrap();

        assert_eq!(unlocked.len(), 0);
        assert_eq!(locked.len(), 2);

        // Compare in any order
        for created_item in created_items.iter() {
            assert!(locked.contains(created_item));
        }

        run_server_handle.abort();
        assert!(run_server_handle.await.unwrap_err().is_cancelled());

        Ok(())
    }
}
