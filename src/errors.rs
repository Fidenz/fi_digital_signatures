/// The private key identification failed
pub const PRIVATE_KEY_IDENTIFICATION_ERROR: &'static str = "Error identifying private key";

/// The public key identification failed
pub const PUBLIC_KEY_IDENTIFICATION_ERROR: &'static str = "Error identifying public key";

/// Provided algorithm either isn't identifiable or not supported
pub const UNKNOWN_ALGORITHM: &'static str = "Unusable or unidentified algorithm";

/// Failed to sign the requested content
pub const SIGNING_FAILED: &'static str = "Failed to sign the content";

/// Base64 encoding is wrong
pub const ENCODING_ERROR: &'static str = "Invalid encoding";

/// Base64 decoding is wrong
pub const DECODING_ERROR: &'static str = "Invalid decoding";

/// Failed to identify the provided signature
pub const SIGNATURE_IDENTIFICATION_FAILED: &'static str = "Failed to identify the signature";

/// Elliptic curve public/private pem file containes errors
pub const EC_PEM_ERROR: &'static str = "Failed to parse EC pem";

/// Failed to deserialize JWT header [`crate::jwt::Header`]
pub const JWT_HEADER_DESERIALIZING_ERROR: &'static str = "Failed to deserialize jwt header";

/// Failed to deserialize JWT header [`crate::jwt::Payload`]
pub const JWT_PAYLOAD_DESERIALIZING_ERROR: &'static str = "Failed to deserialize jwt payload";

/// JWT token has expired
pub const JWT_EXPIRED: &'static str = "JWT token is expired";

/// JWT content is not in UTF8 characters
pub const JWT_UTF8_ERROR: &'static str = "Base64 decoded JWT content is not utf8";

/// No signature found for the JWT token
pub const JWT_NO_SIGNATURE_FOUND: &'static str = "JWT signature not found";

/// Unsigned JWT token
pub const JWT_TOKEN_NOT_SIGNED: &'static str = "Unsigned JWT token";

/// Expiration date field <br>'exp'</br> is missing in payload
pub const JWT_PAYLOAD_MISSING_FIELD_EXP: &'static str = "JWT payload is missing the \"exp\" field";

/// Expiration date field <br>'exp'</br> can't be extracted from the payload
pub const JWT_PAYLOAD_FIELD_EXP_IDENTIFICATION_ERROR: &'static str =
    "JWT can't extract the value for field \"exp\"";

/// Couldn't identify the algorithm from JWT header
pub const FAILED_TO_IDENTIFY_ALGORITHM: &'static str = "Failed to identify the algorithm used";

/// Failed to convert <br>'exp'</br> timestamp to rust datetime
pub const FAILED_TO_CONVERT_TIMESTAMP_TO_DATETTIME: &'static str =
    "Failed to convert the timestamp number into a datetime instance";

/// Failed to create HMAC key
pub const HMAC_KEY_ERROR: &'static str = "Failed to create the HMAC key";

/// Invalid signing key instance
pub const NOT_A_SIGNING_KEY_INSTANCE: &'static str = "Provided value is not a signing key instace";

/// Invalid verifying key instance
pub const NOT_A_VERIFYING_KEY_INSTANCE: &'static str =
    "Provided value is not a verifying key instace";

/// Missing field in Js object
pub const MISSING_FIELD: &'static str = "Provided JS object is missing some required fields";

/// Failed to deserialize json string
pub const JSON_DESERIALIZATION_FAILED: &'static str = "Failed to deserialize provided json string";

///
pub const NOT_USING_ASYMMETRIC_KEYS: &'static str = "This algorithm doesn't use asymmetric keys.";
