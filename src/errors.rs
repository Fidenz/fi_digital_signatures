use std::fmt::Display;

#[derive(Debug)]
pub struct Error(&'static str);

impl Error {
    pub const PRIVATE_KEY_IDENTIFICATION_ERROR: Error = Error("Error identifying private key");
    pub const PUBLIC_KEY_IDENTIFICATION_ERROR: Error = Error("Error identifying public key");
    pub const UNKNOWN_ALGORITHM: Error = Error("Unusable or unidentified algorithm");
    pub const SIGNING_FAILED: Error = Error("Failed to sign the content");
    pub const ENCODING_ERROR: Error = Error("Invalid encoding");
    pub const DECODING_ERROR: Error = Error("Invalid decoding");
    pub const SIGNATURE_IDENTIFICATION_FAILED: Error = Error("Failed to identify the signature");
    pub const EC_PEM_ERROR: Error = Error("Failed to parse EC pem");
    pub const JWT_HEADER_DESERIALIZING_ERROR: Error = Error("Failed to deserialize jwt header");
    pub const JWT_PAYLOAD_DESERIALIZING_ERROR: Error = Error("Failed to deserialize jwt payload");
    pub const JWT_EXPIRED: Error = Error("JWT token is expired");
    pub const JWT_UTF8_ERROR: Error = Error("Base64 decoded JWT content is not utf8");
    pub const JWT_NO_SIGNATURE_FOUND: Error = Error("JWT signature not found");
    pub const JWT_TOKEN_NOT_SIGNED: Error = Error("Unsigned JWT token");
    pub const JWT_PAYLOAD_MISSING_FIELD_EXP: Error =
        Error("JWT payload is missing the \"exp\" field");
    pub const JWT_PAYLOAD_FIELD_EXP_IDENTIFICATION_ERROR: Error =
        Error("JWT can't extract the value for field \"exp\"");
    pub const FAILED_TO_IDENTIFY_ALGORITHM: Error = Error("Failed to identify the algorithm used");
    pub const FAILED_TO_CONVERT_TIMESTAMP_TO_DATETTIME: Error =
        Error("Failed to convert the timestamp number into a datetime instance");
    pub const HMAC_KEY_ERROR: Error = Error("Failed to create the HMAC key");
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
