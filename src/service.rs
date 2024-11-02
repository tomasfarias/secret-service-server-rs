use std::collections;
use std::str;

use crate::collection;
use crate::error;
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

    pub fn add_session(&mut self, session: session::Session) -> &session::Session {
        let key = session.object_path.as_ref().to_string();

        self.sessions.insert(key.clone(), session);
        self.sessions
            .get(&key)
            .expect("key must exist as it was just inserted")
    }

    pub fn add_collection(
        &mut self,
        collection: collection::Collection,
    ) -> Result<&collection::Collection, error::Error> {
        let key = collection.object_path.as_ref().to_string();

        if let Some(alias) = collection.alias.as_ref() {
            self.add_collection_alias(&collection.object_path.as_ref(), alias)?;
        }

        self.collections.insert(key.clone(), collection);
        Ok(self
            .collections
            .get(&key)
            .expect("key must exist as it was just inserted"))
    }

    pub fn add_collection_alias(
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
        if alias != "" {
            if let Some(collection_key) = self.aliases.get(alias) {
                Ok((
                    self.collections
                        .get(collection_key)
                        .expect("alias is added with each collection")
                        .object_path
                        .as_ref(),
                    zvariant::ObjectPath::try_from("/").unwrap(),
                ))
            } else {
                let collection_id = uuid::Uuid::new_v4();
                let new_collection = collection::Collection::new(
                    &collection_id,
                    &properties.label,
                    Some(alias),
                    &self,
                );
                let added_collection = self.add_collection(new_collection)?;

                emitter.collection_created().await?;

                Ok((
                    added_collection.object_path.as_ref(),
                    zvariant::ObjectPath::try_from("/").unwrap(),
                ))
            }
        } else {
            let collection_id = uuid::Uuid::new_v4();
            let new_collection =
                collection::Collection::new(&collection_id, &properties.label, None, &self);
            let added_collection = self.add_collection(new_collection)?;

            emitter.collection_created().await?;

            Ok((
                added_collection.object_path.as_ref(),
                zvariant::ObjectPath::try_from("/").unwrap(),
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
                        zvariant::OwnedObjectPath::try_from(item_str).unwrap(),
                        secret,
                    );
                }
            }
        }

        Ok(secrets_map)
    }

    /// Lock method
    async fn lock(
        &self,
        objects: Vec<zvariant::ObjectPath<'_>>,
    ) -> (Vec<zvariant::OwnedObjectPath>, zvariant::OwnedObjectPath) {
        (Vec::new(), zvariant::OwnedObjectPath::default())
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
                let session = session::Session::new(&session_id).plain();
                let added_session = self.add_session(session);

                Ok((
                    zvariant::Value::new("").try_to_owned().unwrap(),
                    added_session.object_path.as_ref(),
                ))
            }
            "dh-ietf1024-sha256-aes128-cbc-pkcs7" => {
                let (session, server_public_key) = session::Session::new(&session_id)
                    .dh(public_key.as_str().as_bytes().try_into().unwrap());
                let added_session = self.add_session(session);

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
            zvariant::OwnedObjectPath::try_from(matching_collection.as_str()).unwrap()
        } else {
            zvariant::OwnedObjectPath::try_from("/").unwrap()
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
                            unlocked
                                .push(zvariant::OwnedObjectPath::try_from(path.as_str()).unwrap())
                        } else {
                            locked.push(zvariant::OwnedObjectPath::try_from(path.as_str()).unwrap())
                        }
                    }
                }
            }
        }

        (unlocked, locked)
    }

    /// SetAlias method
    fn set_alias(&mut self, name: &str, collection: zvariant::ObjectPath<'_>) {}

    /// Unlock method
    fn unlock(
        &self,
        objects: Vec<zvariant::ObjectPath<'_>>,
    ) -> (Vec<zvariant::OwnedObjectPath>, zvariant::OwnedObjectPath) {
        (Vec::new(), zvariant::OwnedObjectPath::default())
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
