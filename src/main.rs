use std::env;
use std::path;

mod collection;
mod error;
mod item;
mod secret;
mod service;
mod session;

#[derive(Debug)]
pub struct SecretServiceServer {
    connection: zbus::Connection,
    dbus_name: String,
}

impl SecretServiceServer {
    pub async fn new(dbus_name: &str) -> Result<Self, error::Error> {
        let connection = zbus::Connection::session().await?;

        Ok(Self {
            connection,
            dbus_name: dbus_name.to_owned(),
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

        loop {
            // Handling D-Bus messages is done in the background
            std::future::pending::<()>().await;
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), error::Error> {
    let config_folder = env::var("XDG_CONFIG_HOME").unwrap_or_else(|_| "$HOME/.config".to_string());
    let mut config_path = path::PathBuf::new();
    config_path.push(&config_folder);
    config_path.push("secret-service-server");

    let mut builder = config::Config::builder()
        .set_default("log_level", "INFO")?
        .set_default("dbus_name", "org.freedesktop.secrets")?
        .add_source(config::Environment::with_prefix("sss"));

    builder = if config_path.exists() {
        builder.add_source(config::File::from(config_path))
    } else {
        builder
    };
    let settings = builder.build()?;

    structured_logger::Builder::with_level(
        &settings
            .get_string("log_level")
            .expect("log_level defaults to 'INFO'"),
    )
    .with_target_writer(
        "*",
        structured_logger::async_json::new_writer(tokio::io::stdout()),
    )
    .init();

    let dbus_name: String = settings
        .get("dbus_name")
        .expect("dus_name defaults to 'org.freedesktop.secrets'");
    let server = SecretServiceServer::new(&dbus_name).await?;
    server.run().await?;

    Ok(())
}
