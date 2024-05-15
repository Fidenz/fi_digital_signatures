use crate::{algorithms::Algorithm, errors::Error};

/// ECDSA based algorithms signing and verifying
pub mod ecdsa;
/// ed25519 algorithm signing and verifying
pub mod eddsa;
/// HMAC and verifying
pub mod hmac;
/// RSA signing and verifying
pub mod rsa;

/// Common trait that distributes the <b>sign</b> function into [`crate::crypto::ecdsa`], [`crate::crypto::eddsa`], [`crate::crypto::hmac`], [`crate::crypto::rsa`]
pub trait SignFromKey {
    /// Sign the content with the provided algorithm using this key
    fn sign(&self, content: String, alg: Algorithm) -> Result<String, Error>;
}

/// Common trait that distributes the <b>verify</b> function into [`crate::crypto::ecdsa`], [`crate::crypto::eddsa`], [`crate::crypto::hmac`], [`crate::crypto::rsa`]
pub trait VerifyFromKey {
    /// Verify the signature with the provided algorithm using this key
    fn verify(&self, content: String, signature: String, alg: Algorithm) -> Result<bool, Error>;
}
