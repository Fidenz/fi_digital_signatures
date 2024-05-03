use std::fmt::Display;

pub struct Error(&'static str);

impl Error {
    pub const PRIVATE_KEY_IDENTIFICATION_ERROR: Error = Error("Error identifying private key");
    pub const UNKNOWN_ALGORITHM: Error = Error("Unusable or unidentified algorithm");
    pub const SIGNING_FAILED: Error = Error("Failed to sign the content");
    pub const ENCODING_ERROR: Error = Error("Invalid encoding");
    pub const DECODING_ERROR: Error = Error("Invalid decoding");
    pub const SIGNATURE_IDENTIFICATION_FAILED: Error = Error("Failed to identify the signature");
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
