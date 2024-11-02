#[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize, zvariant::Type)]
pub struct Secret {
    pub session: zvariant::OwnedObjectPath,
    pub value: Vec<u8>,
    pub parameters: Vec<u8>,
    pub content_type: String,
}
