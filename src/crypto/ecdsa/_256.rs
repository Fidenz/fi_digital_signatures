use std::str::FromStr;

use crate::{
    algorithms::Algorithm,
    crypto::{SignFromKey, VerifyFromKey},
    errors::Error,
    log,
};
use elliptic_curve::pkcs8::DecodePublicKey;
use p256::{
    ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey},
    NistP256,
};

/// Signing key for [`crate::algorithms::Algorithm::ES256`]
pub struct P256SigningKey {
    pub key: SigningKey,
}

impl SignFromKey for P256SigningKey {
    fn sign(&self, content: String, _alg: Algorithm) -> Result<String, Error> {
        let sig_result: Result<Signature, p256::ecdsa::Error> =
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

impl P256SigningKey {
    /// Create Signing key from pem formatted private key. <b>pkcs8</b> and <b>pkcs1</b>.
    pub fn from_pem(key_str: &str) -> Result<Self, Error> {
        let ec_key = match key_str.starts_with("-----BEGIN EC PRIVATE KEY-----") {
            true => {
                let key_scalar: elliptic_curve::SecretKey<NistP256> =
                    match elliptic_curve::SecretKey::from_sec1_pem(key_str) {
                        Ok(val) => val,
                        Err(error) => {
                            log::error(error.to_string().as_str());
                            return Err(Error::EC_PEM_ERROR);
                        }
                    };

                match SigningKey::from_bytes(&key_scalar.as_scalar_primitive().to_bytes()) {
                    Ok(val) => val,
                    Err(error) => {
                        log::error(error.to_string().as_str());
                        return Err(Error::PRIVATE_KEY_IDENTIFICATION_ERROR);
                    }
                }
            }
            false => {
                let key_scalar: elliptic_curve::SecretKey<NistP256> =
                    match elliptic_curve::SecretKey::from_str(key_str) {
                        Ok(val) => val,
                        Err(error) => {
                            log::error(error.to_string().as_str());
                            return Err(Error::EC_PEM_ERROR);
                        }
                    };

                match SigningKey::from_bytes(&key_scalar.as_scalar_primitive().to_bytes()) {
                    Ok(val) => val,
                    Err(error) => {
                        log::error(error.to_string().as_str());
                        return Err(Error::PRIVATE_KEY_IDENTIFICATION_ERROR);
                    }
                }
            }
        };

        Ok(P256SigningKey { key: ec_key })
    }

    /// Create Signing key from private key bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let ec_key = match SigningKey::from_slice(bytes) {
            Ok(val) => val,
            Err(error) => {
                log::error(error.to_string().as_str());
                return Err(Error::PUBLIC_KEY_IDENTIFICATION_ERROR);
            }
        };
        Ok(P256SigningKey { key: ec_key })
    }
}

/// Verifying key for [`crate::algorithms::Algorithm::ES256`]
pub struct P256VerifyingKey {
    key: VerifyingKey,
}

impl VerifyFromKey for P256VerifyingKey {
    fn verify(&self, content: String, signature: String, _alg: Algorithm) -> Result<bool, Error> {
        let decoded_sig = match base64_url::decode(signature.as_bytes()) {
            Ok(val) => val,
            Err(error) => {
                log::error(error.to_string().as_str());
                return Err(Error::DECODING_ERROR);
            }
        };

        let sig = match Signature::from_slice(&decoded_sig) {
            Ok(val) => val,
            Err(error) => {
                log::error(error.to_string().as_str());
                return Err(Error::SIGNATURE_IDENTIFICATION_FAILED);
            }
        };

        let verify_result: Result<(), p256::ecdsa::Error> =
            self.key.verify(content.as_bytes(), &sig);
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

impl P256VerifyingKey {
    /// Create verifying key from pem formated key. <b>pkcs8</b> only.
    pub fn from_pem(key_str: &str) -> Result<Self, Error> {
        let key_scalar: elliptic_curve::PublicKey<NistP256> =
            match elliptic_curve::PublicKey::from_public_key_pem(key_str) {
                Ok(val) => val,
                Err(error) => {
                    log::error(error.to_string().as_str());
                    return Err(Error::EC_PEM_ERROR);
                }
            };

        let ec_key = match VerifyingKey::from_sec1_bytes(&key_scalar.to_sec1_bytes()) {
            Ok(val) => val,
            Err(error) => {
                log::error(error.to_string().as_str());
                return Err(Error::PUBLIC_KEY_IDENTIFICATION_ERROR);
            }
        };
        Ok(P256VerifyingKey { key: ec_key })
    }

    /// Create verifying key from key bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let ec_key = match VerifyingKey::from_sec1_bytes(bytes) {
            Ok(val) => val,
            Err(error) => {
                log::error(error.to_string().as_str());
                return Err(Error::PUBLIC_KEY_IDENTIFICATION_ERROR);
            }
        };

        Ok(P256VerifyingKey { key: ec_key })
    }
}

/// Sign content using [`crate::algorithms::Algorithm::ES256`] algorithm
pub fn ec_256_sign(message: String, key: impl SignFromKey) -> Result<String, Error> {
    key.sign(message, Algorithm::ES256)
}

/// Verify signature using [`crate::algorithms::Algorithm::ES256`] algorithm
pub fn ec_256_verify(message: String, sig: String, key: impl VerifyFromKey) -> Result<bool, Error> {
    key.verify(message, sig, Algorithm::ES256)
}
