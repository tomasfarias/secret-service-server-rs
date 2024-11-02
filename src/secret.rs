//! A secret type to hold a (possibly) encoded secret and its parameters.
//!
//! Based on: https://specifications.freedesktop.org/secret-service-spec/latest/types.html#id-1.3.4.2.
#[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize, zvariant::Type)]
pub struct Secret {
    pub session: zvariant::OwnedObjectPath,
    pub value: Vec<u8>,
    pub parameters: Vec<u8>,
    pub content_type: String,
}
