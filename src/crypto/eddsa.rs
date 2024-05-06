use ed25519_dalek::{
    pkcs8::DecodePrivateKey, pkcs8::DecodePublicKey, Signer, SigningKey, Verifier,
};
use ed25519_dalek::{Signature, VerifyingKey};

use crate::errors::Error;
use crate::log;

pub fn sign_eddsa(message: String, key: String) -> Result<String, Error> {
    let pkc8_key = match SigningKey::from_pkcs8_pem(key.as_str()) {
        Ok(val) => val,
        Err(error) => {
            log::error(error.to_string().as_str());
            return Err(Error::PRIVATE_KEY_IDENTIFICATION_ERROR);
        }
    };

    let sig_result: Result<Signature, ed25519_dalek::ed25519::Error> =
        pkc8_key.try_sign(message.as_bytes());
    let signature = match sig_result {
        Ok(val) => val,
        Err(error) => {
            log::error(error.to_string().as_str());
            return Err(Error::SIGNING_FAILED);
        }
    };

    Ok(base64_url::encode(signature.to_bytes().as_slice()))
}

pub fn verify_eddsa(message: String, sig: String, key: String) -> Result<bool, Error> {
    let pkc8_key = match VerifyingKey::from_public_key_pem(key.as_str()) {
        Ok(val) => val,
        Err(error) => {
            log::error(error.to_string().as_str());
            return Err(Error::PUBLIC_KEY_IDENTIFICATION_ERROR);
        }
    };

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
        pkc8_key.verify(message.as_bytes(), &signature);
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
