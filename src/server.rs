use crate::error;
use crate::object::collection;
use crate::object::service;
use crate::object::DbusObject;

#[derive(Debug)]
pub struct SecretServiceServer {
    connection: zbus::Connection,
    dbus_name: String,
    start_event: event_listener::Event,
}

impl SecretServiceServer {
    pub async fn new(
        dbus_name: &str,
        start_event: event_listener::Event,
    ) -> Result<Self, error::Error> {
        let connection = zbus::Connection::session().await?;

        Ok(Self {
            connection,
            dbus_name: dbus_name.to_owned(),
            start_event,
        })
    }

    pub async fn run(self) -> Result<(), error::Error> {
        let service = service::Service::new();
        let (interface_path, _) = service.serve_at(self.connection.object_server()).await?;

        log::info!("Serving Secret Service interface.");

        {
            let interface = service::Service::get_interface_from_object_path(
                &interface_path.as_ref(),
                self.connection.object_server(),
            )
            .await?;

            let properties = collection::CollectionReadWriteProperties {
                label: "default".to_owned(),
            };

            interface
                .get_mut()
                .await
                .create_collection(
                    properties,
                    "default",
                    self.connection.object_server(),
                    interface.signal_emitter().to_owned(),
                )
                .await?;
        }
        log::info!("Created default collection.");

        let dbus_name = self.dbus_name;
        self.connection.request_name(dbus_name.as_str()).await?;

        log::info!("Dbus assigned name '{dbus_name}' to secret service server");

        self.start_event.notify(usize::MAX);

        loop {
            // Handling D-Bus messages is done in the background
            std::future::pending::<()>().await;
        }
    }
}
