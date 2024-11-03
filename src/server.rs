use crate::error;
use crate::service;

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
        let mut interface = service::Service::new();
        interface.create_default_collection()?;
        let service_path = interface.object_path.clone();

        let dbus_name = self.dbus_name;
        self.connection
            .object_server()
            .at(&service_path, interface)
            .await?;

        self.connection.request_name(dbus_name.as_str()).await?;

        log::info!("Dbus assigned name '{dbus_name}' to secret service server");

        self.start_event.notify(usize::MAX);

        loop {
            // Handling D-Bus messages is done in the background
            std::future::pending::<()>().await;
        }
    }
}
