use std::fmt;
use zbus::DBusError;

#[derive(Debug)]
pub enum Error {
    AlgorithmUnsupported(String),
    ItemExists(String),
    ItemIsDeleted(String),
    CollectionAliasExists(String),
    CollectionIsDeleted(String),
    Config(config::ConfigError),
    IsLocked(String),
    NoSession(String),
    NoSuchObject(String),
    SessionIsClosed,
    Zbus(zbus::Error),
    Zvariant(zvariant::Error),
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
                zbus_names::ErrorName::try_from("org.freedesktop.DBus.Error.NotSupported")
                    .expect("well-known error name")
            }
            Error::IsLocked(_) => {
                zbus_names::ErrorName::try_from("org.freedesktop.Secret.Error.IsLocked")
                    .expect("well-known error name from the Secret Service spec")
            }
            Error::NoSession(_) => {
                zbus_names::ErrorName::try_from("org.freedesktop.Secret.Error.NoSession")
                    .expect("well-known error name from the Secret Service spec")
            }
            // Although `org.freedesktop.DBus.Error.UnknownObject` would also work here,
            // the secret service spec defines a more precise error for these cases.
            // https://specifications.freedesktop.org/secret-service-spec/latest/errors.html#id-1.3.5.5
            Error::NoSuchObject(_) | Error::ItemIsDeleted(_) | Error::CollectionIsDeleted(_) => {
                zbus_names::ErrorName::try_from("org.freedesktop.Secret.Error.NoSuchObject")
                    .expect("well-known error name from the Secret Service spec")
            }
            _ => zbus_names::ErrorName::try_from("org.freedesktop.DBus.Error.Failed")
                .expect("well-known error name"),
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
                "Cannot open a session with unsupported algorithm: '{}'",
                algorithm
            ),
            Error::IsLocked(object_path) => write!(
                f,
                "The object '{}' must be unlocked before this action can be carried out",
                object_path
            ),
            Error::ItemExists(object_path) => write!(
                f,
                "The item '{}' already exists and not asked to replace",
                object_path
            ),
            Error::CollectionAliasExists(alias) => {
                write!(f, "A collection with alias '{}' already exists", alias)
            }
            Error::Config(inner) => write!(f, "{}", inner),
            Error::NoSuchObject(object)
            | Error::ItemIsDeleted(object)
            | Error::CollectionIsDeleted(object) => {
                write!(f, "No such object exists: '{}'", object)
            }
            Error::NoSession(object_path) => {
                write!(f, "A session '{}' does not exist", object_path)
            }
            Error::SessionIsClosed => write!(f, "Session cannot be used as it is closed"),

            Error::Zbus(inner) => write!(f, "{}", inner),
            Error::Zvariant(inner) => write!(f, "{}", inner),
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

impl From<zvariant::Error> for Error {
    fn from(value: zvariant::Error) -> Error {
        Error::Zvariant(value)
    }
}

impl From<config::ConfigError> for Error {
    fn from(value: config::ConfigError) -> Error {
        Error::Config(value)
    }
}
