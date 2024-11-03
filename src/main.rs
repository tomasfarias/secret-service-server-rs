use std::env;
use std::path;

mod collection;
mod error;
mod item;
mod secret;
mod server;
mod service;
mod session;

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

    let server = server::SecretServiceServer::new(&dbus_name, event_listener::Event::new()).await?;
    server.run().await?;

    Ok(())
}
