pub enum RegistryError {
    ReservedCommId(u8, String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CodecError {
    UnknownVersion,
    UnknownCommunicationType(String),
    UnknownDataType(String),
    ReservedCommunicationType(u8),
    InvalidEncoding,
}
