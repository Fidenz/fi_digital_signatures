use crate::{algorithms::Algorithm, errors::Error};

pub mod ecdsa;
pub mod eddsa;
pub mod hmac;
pub mod rsa;

pub trait SignFromKey {
    fn sign(&self, content: String, alg: Algorithm) -> Result<String, Error>;
}

pub trait VerifyFromKey {
    fn verify(&self, content: String, signature: String, alg: Algorithm) -> Result<bool, Error>;
}
