use ed25519_dalek::{
    pkcs8::DecodePrivateKey, pkcs8::DecodePublicKey, Signer, SigningKey, Verifier,
};
use ed25519_dalek::{Signature, VerifyingKey};

use crate::algorithms::Algorithm;
use crate::errors::Error;
use crate::log;

use super::{SignFromKey, VerifyFromKey};

pub struct EDDSASigningKey {
    key: SigningKey,
}

impl SignFromKey for EDDSASigningKey {
    fn sign(&self, content: String, _alg: Algorithm) -> Result<String, Error> {
        let sig_result: Result<Signature, ed25519_dalek::ed25519::Error> =
            self.key.try_sign(content.as_bytes());
        let signature = match sig_result {
            Ok(val) => val,
            Err(error) => {
                log::error(error.to_string().as_str());
                return Err(Error::SIGNING_FAILED);
            }
        };

        Ok(base64_url::encode(signature.to_bytes().as_slice()))
    }
}

impl EDDSASigningKey {
    pub fn from_pem(key_str: &str) -> Result<Self, Error> {
        let pkc8_key = match SigningKey::from_pkcs8_pem(key_str) {
            Ok(val) => val,
            Err(error) => {
                log::error(error.to_string().as_str());
                return Err(Error::PRIVATE_KEY_IDENTIFICATION_ERROR);
            }
        };

        Ok(EDDSASigningKey { key: pkc8_key })
    }
}

pub struct EDDSAVerifyingKey {
    key: VerifyingKey,
}

impl VerifyFromKey for EDDSAVerifyingKey {
    fn verify(&self, content: String, sig: String, _alg: Algorithm) -> Result<bool, Error> {
        let decoded_sig = match base64_url::decode(sig.as_bytes()) {
            Ok(val) => val,
            Err(error) => {
                log::error(error.to_string().as_str());
                return Err(Error::DECODING_ERROR);
            }
        };

        let signature = match Signature::from_slice(&decoded_sig) {
            Ok(val) => val,
            Err(error) => {
                log::error(error.to_string().as_str());
                return Err(Error::SIGNATURE_IDENTIFICATION_FAILED);
            }
        };

        let verify_result: Result<(), ed25519_dalek::ed25519::Error> =
            self.key.verify(content.as_bytes(), &signature);
        if verify_result.is_ok() {
            return Ok(true);
        } else {
            match verify_result.err() {
                Some(error) => {
                    log::error(error.to_string().as_str());
                }
                None => {}
            };
            return Ok(false);
        }
    }
}

impl EDDSAVerifyingKey {
    pub fn from_pem(key_str: &str) -> Result<Self, Error> {
        let pkc8_key = match VerifyingKey::from_public_key_pem(key_str) {
            Ok(val) => val,
            Err(error) => {
                log::error(error.to_string().as_str());
                return Err(Error::PUBLIC_KEY_IDENTIFICATION_ERROR);
            }
        };

        Ok(EDDSAVerifyingKey { key: pkc8_key })
    }
}

pub fn sign_eddsa(message: String, key: impl SignFromKey, alg: Algorithm) -> Result<String, Error> {
    key.sign(message, alg)
}

pub fn verify_eddsa(
    message: String,
    sig: String,
    key: impl VerifyFromKey,
    alg: Algorithm,
) -> Result<bool, Error> {
    key.verify(message, sig, alg)
}
