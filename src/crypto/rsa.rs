use crate::algorithms::Algorithm;
use crate::errors::Error;
use crate::log;
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use rsa::pkcs1v15::Signature;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::sha2::{Sha256, Sha384, Sha512};
use rsa::signature::{RandomizedSigner, SignatureEncoding, SignerMut, Verifier};

pub fn sign_rsa(message: String, key_str: String, alg: Algorithm) -> Result<String, Error> {
    let rsa_key = match key_str.starts_with("-----BEGIN RSA PRIVATE KEY-----") {
        true => match rsa::RsaPrivateKey::from_pkcs1_pem(key_str.as_str()) {
            Ok(val) => val,
            Err(error) => {
                log::error(error.to_string().as_str());
                return Err(Error::PRIVATE_KEY_IDENTIFICATION_ERROR);
            }
        },
        false => match rsa::RsaPrivateKey::from_pkcs8_pem(key_str.as_str()) {
            Ok(val) => val,
            Err(error) => {
                log::error(error.to_string().as_str());
                return Err(Error::PRIVATE_KEY_IDENTIFICATION_ERROR);
            }
        },
    };

    let mut rng = rand::thread_rng();
    if alg.to_str().starts_with("RS") {
        let sig: Signature = match alg {
            Algorithm::RS256 => {
                let mut signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(rsa_key);
                signing_key.sign(message.as_bytes())
            }
            Algorithm::RS384 => {
                let mut signing_key = rsa::pkcs1v15::SigningKey::<Sha384>::new(rsa_key);
                signing_key.sign(message.as_bytes())
            }
            Algorithm::RS512 => {
                let mut signing_key = rsa::pkcs1v15::SigningKey::<Sha512>::new(rsa_key);
                signing_key.sign(message.as_bytes())
            }
            _ => return Err(Error::UNKNOWN_ALGORITHM),
        };
        let bytes = sig.to_bytes();
        Ok(base64_url::encode(&bytes))
    } else {
        let sig = match alg {
            Algorithm::PS256 => {
                let signing_key = rsa::pss::SigningKey::<Sha256>::new(rsa_key);
                signing_key.sign_with_rng(&mut rng, message.as_bytes())
            }
            Algorithm::PS384 => {
                let signing_key = rsa::pss::SigningKey::<Sha384>::new(rsa_key);
                signing_key.sign_with_rng(&mut rng, message.as_bytes())
            }
            Algorithm::PS512 => {
                let signing_key = rsa::pss::SigningKey::<Sha512>::new(rsa_key);
                signing_key.sign_with_rng(&mut rng, message.as_bytes())
            }
            _ => return Err(Error::UNKNOWN_ALGORITHM),
        };

        let bytes = sig.to_bytes();
        Ok(base64_url::encode(&bytes))
    }
}

pub fn verify_rsa(
    message: String,
    signature: String,
    key_str: String,
    alg: Algorithm,
) -> Result<bool, Error> {
    let rsa_key = match key_str.starts_with("-----BEGIN RSA PUBLIC KEY-----") {
        true => match rsa::RsaPublicKey::from_pkcs1_pem(key_str.as_str()) {
            Ok(val) => val,
            Err(error) => {
                log::error(error.to_string().as_str());
                return Err(Error::PRIVATE_KEY_IDENTIFICATION_ERROR);
            }
        },
        false => match rsa::RsaPublicKey::from_public_key_pem(key_str.as_str()) {
            Ok(val) => val,
            Err(error) => {
                log::error(error.to_string().as_str());
                return Err(Error::PRIVATE_KEY_IDENTIFICATION_ERROR);
            }
        },
    };

    let decoded_sig_data = match base64_url::decode(&signature) {
        Ok(val) => val,
        Err(error) => {
            log::error(error.to_string().as_str());
            return Err(Error::DECODING_ERROR);
        }
    };

    if alg.to_str().starts_with("RS") {
        let sig = match rsa::pkcs1v15::Signature::try_from(decoded_sig_data.as_slice()) {
            Ok(val) => val,
            Err(error) => {
                log::error(error.to_string().as_str());
                return Err(Error::SIGNATURE_IDENTIFICATION_FAILED);
            }
        };

        let verification = match alg {
            Algorithm::RS256 => {
                let verifying_key = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(rsa_key);
                verifying_key.verify(message.as_bytes(), &sig)
            }
            Algorithm::RS384 => {
                let verifying_key = rsa::pkcs1v15::VerifyingKey::<Sha384>::new(rsa_key);
                verifying_key.verify(message.as_bytes(), &sig)
            }
            Algorithm::RS512 => {
                let verifying_key = rsa::pkcs1v15::VerifyingKey::<Sha512>::new(rsa_key);
                verifying_key.verify(message.as_bytes(), &sig)
            }
            _ => return Err(Error::UNKNOWN_ALGORITHM),
        };

        if verification.is_ok() {
            return Ok(true);
        } else {
            match verification.err() {
                Some(val) => {
                    log::error(val.to_string().as_str());
                }
                None => {}
            }
            return Ok(false);
        }
    } else {
        let sig = match rsa::pss::Signature::try_from(decoded_sig_data.as_slice()) {
            Ok(val) => val,
            Err(error) => {
                log::error(error.to_string().as_str());
                return Err(Error::SIGNATURE_IDENTIFICATION_FAILED);
            }
        };

        let verification = match alg {
            Algorithm::RS256 => {
                let verifying_key = rsa::pss::VerifyingKey::<Sha256>::new(rsa_key);
                verifying_key.verify(message.as_bytes(), &sig)
            }
            Algorithm::RS384 => {
                let verifying_key = rsa::pss::VerifyingKey::<Sha384>::new(rsa_key);
                verifying_key.verify(message.as_bytes(), &sig)
            }
            Algorithm::RS512 => {
                let verifying_key = rsa::pss::VerifyingKey::<Sha512>::new(rsa_key);
                verifying_key.verify(message.as_bytes(), &sig)
            }
            _ => return Err(Error::UNKNOWN_ALGORITHM),
        };

        if verification.is_ok() {
            return Ok(true);
        } else {
            match verification.err() {
                Some(val) => {
                    log::error(val.to_string().as_str());
                }
                None => {}
            }
            return Ok(false);
        }
    }
}
