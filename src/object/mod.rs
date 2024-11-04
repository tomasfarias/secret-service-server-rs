use std::collections;

pub mod collection;
pub mod item;
pub mod service;
pub mod session;

use crate::error;

pub trait SecretServiceDbusObject: zbus::object_server::Interface {
    fn get_object_path(&self) -> zvariant::OwnedObjectPath;

    async fn serve_at(
        self,
        object_server: &zbus::ObjectServer,
    ) -> Result<(zvariant::OwnedObjectPath, bool), error::Error>
    where
        Self: Sized,
    {
        let object_path = self.get_object_path();
        let exists = object_server.at(object_path.clone(), self).await?;
        Ok((object_path, exists))
    }

    async fn remove<I: zbus::object_server::Interface>(
        &self,
        object_server: &zbus::ObjectServer,
    ) -> Result<bool, error::Error> {
        let object_path = self.get_object_path();
        Ok(object_server
            .remove::<I, zvariant::OwnedObjectPath>(object_path)
            .await?)
    }

    async fn get_interface_from_object_path<'p>(
        object_path: &'p zvariant::ObjectPath<'_>,
        object_server: &'p zbus::ObjectServer,
    ) -> Result<zbus::object_server::InterfaceRef<Self>, error::Error>
    where
        Self: Sized,
    {
        let interface_ref = object_server.interface::<_, Self>(object_path).await?;
        Ok(interface_ref)
    }
}

pub trait SecretServiceParentObject {
    fn get_children(&self) -> &collections::HashSet<zvariant::OwnedObjectPath>;

    fn get_mut_children(&mut self) -> &mut collections::HashSet<zvariant::OwnedObjectPath>;
}

pub trait SecretServiceChildObject: SecretServiceDbusObject {
    type Parent: SecretServiceDbusObject + SecretServiceParentObject;

    fn get_parent_path(&self) -> zvariant::ObjectPath<'_>;

    async fn get_parent_interface(
        &self,
        object_server: &zbus::ObjectServer,
    ) -> Result<zbus::object_server::InterfaceRef<Self::Parent>, error::Error> {
        Self::Parent::get_interface_from_object_path(&self.get_parent_path(), object_server).await
    }

    async fn remove_from_parent(&self, object_server: &zbus::ObjectServer) -> bool {
        if let Ok(parent_interface) = self.get_parent_interface(object_server).await {
            let mut parent = parent_interface.get_mut().await;
            parent.get_mut_children().remove(&self.get_object_path())
        } else {
            false
        }
    }
}
