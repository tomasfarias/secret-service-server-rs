use std::fmt;
use zbus::DBusError;

#[derive(Debug)]
pub enum Error {
    AlgorithmUnsupported(String),
    ItemExists(String),
    ItemIsDeleted,
    CollectionAliasExists(String),
    CollectionIsDeleted,
    ConfigError(config::ConfigError),
    SessionIsClosed,
    Zbus(zbus::Error),
}

impl DBusError for Error {
    fn create_reply(
        &self,
        msg: &zbus::message::Header<'_>,
    ) -> zbus::Result<zbus::message::Message> {
        let message = zbus::message::Message::error(msg, self.name())?.build(&())?;
        Ok(message)
    }

    fn name(&self) -> zbus_names::ErrorName<'_> {
        match self {
            Error::AlgorithmUnsupported(_) => {
                zbus_names::ErrorName::try_from("org.freedesktop.DBus.Error.NotSupported").unwrap()
            }
            _ => zbus_names::ErrorName::try_from("org.freedesktop.DBus.Error.Failed").unwrap(),
        }
    }
    fn description(&self) -> Option<&str> {
        let description = format!("{}", self).leak();
        Some(description)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::AlgorithmUnsupported(algorithm) => write!(
                f,
                "Attempted to open a session with an unsupported algorithm: '{}'",
                algorithm
            ),
            Error::ItemExists(object_path) => write!(
                f,
                "An Item with Object Path '{}' already exists and not asked to replace",
                object_path
            ),
            Error::ItemIsDeleted => write!(f, "Attempted to operate on deleted item"),
            Error::CollectionAliasExists(alias) => {
                write!(f, "A collection with alias '{}' already exists", alias)
            }
            Error::CollectionIsDeleted => write!(f, "Attempted to operate on deleted collection"),
            Error::ConfigError(inner) => write!(f, "{}", inner),
            Error::SessionIsClosed => write!(f, "Session cannot be used as it is closed"),
            Error::Zbus(inner) => write!(f, "{}", inner),
        }
    }
}

impl From<Error> for zbus::fdo::Error {
    fn from(value: Error) -> zbus::fdo::Error {
        zbus::fdo::Error::Failed(format!("{}", value))
    }
}

impl From<zbus::Error> for Error {
    fn from(value: zbus::Error) -> Error {
        Error::Zbus(value)
    }
}

impl From<config::ConfigError> for Error {
    fn from(value: config::ConfigError) -> Error {
        Error::ConfigError(value)
    }
}
