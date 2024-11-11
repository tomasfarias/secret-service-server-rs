use std::collections;

pub mod collection;
pub mod item;
pub mod service;
pub mod session;

use crate::error;

pub trait DbusObject: zbus::object_server::Interface {
    fn get_object_path(&self) -> zvariant::OwnedObjectPath;

    fn serve_at(
        self,
        object_server: &zbus::ObjectServer,
    ) -> impl std::future::Future<Output = Result<(zvariant::OwnedObjectPath, bool), error::Error>> + Send
    where
        Self: Sized,
    {
        async {
            let object_path = self.get_object_path();
            let exists = object_server.at(object_path.clone(), self).await?;
            Ok((object_path, exists))
        }
    }

    fn remove<I: zbus::object_server::Interface>(
        &self,
        object_server: &zbus::ObjectServer,
    ) -> impl std::future::Future<Output = Result<bool, error::Error>> + Send {
        async {
            let object_path = self.get_object_path();
            Ok(object_server
                .remove::<I, zvariant::OwnedObjectPath>(object_path)
                .await?)
        }
    }

    fn get_interface_from_object_path<'p>(
        object_path: &'p zvariant::ObjectPath<'_>,
        object_server: &'p zbus::ObjectServer,
    ) -> impl std::future::Future<
        Output = Result<zbus::object_server::InterfaceRef<Self>, error::Error>,
    > + Send
    where
        Self: Sized,
    {
        async move {
            let interface_ref = object_server.interface::<_, Self>(object_path).await?;
            Ok(interface_ref)
        }
    }
}

pub trait DbusParentObject {
    fn get_children(&self) -> &collections::HashSet<zvariant::OwnedObjectPath>;

    fn get_mut_children(&mut self) -> &mut collections::HashSet<zvariant::OwnedObjectPath>;
}

pub trait DbusChildObject: DbusObject {
    type Parent: DbusObject + DbusParentObject;

    fn get_parent_path(&self) -> zvariant::ObjectPath<'_>;

    fn get_parent_interface(
        &self,
        object_server: &zbus::ObjectServer,
    ) -> impl std::future::Future<
        Output = Result<zbus::object_server::InterfaceRef<Self::Parent>, error::Error>,
    > + Send {
        async {
            Self::Parent::get_interface_from_object_path(&self.get_parent_path(), object_server)
                .await
        }
    }

    fn remove_from_parent(
        &self,
        object_server: &zbus::ObjectServer,
    ) -> impl std::future::Future<Output = bool> + Send {
        async {
            if let Ok(parent_interface) = self.get_parent_interface(object_server).await {
                let mut parent = parent_interface.get_mut().await;
                parent.get_mut_children().remove(&self.get_object_path())
            } else {
                false
            }
        }
    }
}
