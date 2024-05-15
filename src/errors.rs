use std::fmt::Display;

/// Object for error handling
#[derive(Debug)]
pub struct Error(&'static str);

impl Error {
    /// The private key identification failed
    pub const PRIVATE_KEY_IDENTIFICATION_ERROR: Error = Error("Error identifying private key");

    /// The public key identification failed
    pub const PUBLIC_KEY_IDENTIFICATION_ERROR: Error = Error("Error identifying public key");

    /// Provided algorithm either isn't identifiable or not supported
    pub const UNKNOWN_ALGORITHM: Error = Error("Unusable or unidentified algorithm");

    /// Failed to sign the requested content
    pub const SIGNING_FAILED: Error = Error("Failed to sign the content");

    /// Base64 encoding is wrong
    pub const ENCODING_ERROR: Error = Error("Invalid encoding");

    /// Base64 decoding is wrong
    pub const DECODING_ERROR: Error = Error("Invalid decoding");

    /// Failed to identify the provided signature
    pub const SIGNATURE_IDENTIFICATION_FAILED: Error = Error("Failed to identify the signature");

    /// Elliptic curve public/private pem file containes errors
    pub const EC_PEM_ERROR: Error = Error("Failed to parse EC pem");

    /// Failed to deserialize JWT header [`crate::jwt::Header`]
    pub const JWT_HEADER_DESERIALIZING_ERROR: Error = Error("Failed to deserialize jwt header");

    /// Failed to deserialize JWT header [`crate::jwt::Payload`]
    pub const JWT_PAYLOAD_DESERIALIZING_ERROR: Error = Error("Failed to deserialize jwt payload");

    /// JWT token has expired
    pub const JWT_EXPIRED: Error = Error("JWT token is expired");

    /// JWT content is not in UTF8 characters
    pub const JWT_UTF8_ERROR: Error = Error("Base64 decoded JWT content is not utf8");

    /// No signature found for the JWT token
    pub const JWT_NO_SIGNATURE_FOUND: Error = Error("JWT signature not found");

    /// Unsigned JWT token
    pub const JWT_TOKEN_NOT_SIGNED: Error = Error("Unsigned JWT token");

    /// Expiration date field <br>'exp'</br> is missing in payload
    pub const JWT_PAYLOAD_MISSING_FIELD_EXP: Error =
        Error("JWT payload is missing the \"exp\" field");

    /// Expiration date field <br>'exp'</br> can't be extracted from the payload
    pub const JWT_PAYLOAD_FIELD_EXP_IDENTIFICATION_ERROR: Error =
        Error("JWT can't extract the value for field \"exp\"");

    /// Couldn't identify the algorithm from JWT header
    pub const FAILED_TO_IDENTIFY_ALGORITHM: Error = Error("Failed to identify the algorithm used");

    /// Failed to convert <br>'exp'</br> timestamp to rust datetime
    pub const FAILED_TO_CONVERT_TIMESTAMP_TO_DATETTIME: Error =
        Error("Failed to convert the timestamp number into a datetime instance");

    /// Failed to create HMAC key
    pub const HMAC_KEY_ERROR: Error = Error("Failed to create the HMAC key");
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
