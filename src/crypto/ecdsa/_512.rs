use std::str::FromStr;

use crate::{
    algorithms::Algorithm,
    crypto::{SignFromKey, VerifyFromKey},
};
use elliptic_curve::pkcs8::DecodePublicKey;
use fi_common::error::Error;
#[cfg(feature = "wasm")]
use js_sys::{Object, Uint8Array};
use p521::{
    ecdsa::{
        signature::{Signer, Verifier},
        Signature, SigningKey, VerifyingKey,
    },
    NistP521,
};
use wasm_bindgen::prelude::wasm_bindgen;
#[cfg(feature = "wasm")]
use wasm_bindgen::JsValue;

/// Signing key for [`crate::algorithms::Algorithm::ES512`]
#[wasm_bindgen]
pub struct P512SigningKey {
    #[cfg(not(feature = "wasm"))]
    key: SigningKey,

    #[cfg(feature = "wasm")]
    key_str: Option<String>,
    #[cfg(feature = "wasm")]
    key_bytes: Option<Vec<u8>>,
}

impl SignFromKey for P512SigningKey {
    fn sign(&self, content: String, _alg: Algorithm) -> Result<String, Error> {
        #[cfg(not(feature = "wasm"))]
        let key = &self.key;
        #[cfg(feature = "wasm")]
        let key = match self.get_key() {
            Ok(val) => val,
            Err(error) => return Err(error),
        };

        let sig_result: Result<Signature, p521::ecdsa::Error> = key.try_sign(content.as_bytes());
        let signature = match sig_result {
            Ok(val) => val,
            Err(error) => {
                fi_common::logger::error(error.to_string().as_str());
                return Err(Error::new(crate::errors::SIGNING_FAILED));
            }
        };

        Ok(base64_url::encode(signature.to_bytes().as_slice()))
    }
}

fn get_private_key_from_pem(key_str: &str) -> Result<SigningKey, Error> {
    match key_str.starts_with("-----BEGIN EC PRIVATE KEY-----") {
        true => {
            let key_scalar: elliptic_curve::SecretKey<NistP521> =
                match elliptic_curve::SecretKey::from_sec1_pem(key_str) {
                    Ok(val) => val,
                    Err(error) => {
                        fi_common::logger::error(error.to_string().as_str());
                        return Err(Error::new(crate::errors::EC_PEM_ERROR));
                    }
                };

            match SigningKey::from_bytes(&key_scalar.as_scalar_primitive().to_bytes()) {
                Ok(val) => Ok(val),
                Err(error) => {
                    fi_common::logger::error(error.to_string().as_str());
                    return Err(Error::new(crate::errors::PRIVATE_KEY_IDENTIFICATION_ERROR));
                }
            }
        }
        false => {
            let key_scalar: elliptic_curve::SecretKey<NistP521> =
                match elliptic_curve::SecretKey::from_str(key_str) {
                    Ok(val) => val,
                    Err(error) => {
                        fi_common::logger::error(error.to_string().as_str());
                        return Err(Error::new(crate::errors::EC_PEM_ERROR));
                    }
                };

            match SigningKey::from_bytes(&key_scalar.as_scalar_primitive().to_bytes()) {
                Ok(val) => Ok(val),
                Err(error) => {
                    fi_common::logger::error(error.to_string().as_str());
                    return Err(Error::new(crate::errors::PRIVATE_KEY_IDENTIFICATION_ERROR));
                }
            }
        }
    }
}

fn get_private_key_from_bytes(bytes: &[u8]) -> Result<SigningKey, Error> {
    match SigningKey::from_slice(bytes) {
        Ok(val) => Ok(val),
        Err(error) => {
            fi_common::logger::error(error.to_string().as_str());
            return Err(Error::new(crate::errors::PUBLIC_KEY_IDENTIFICATION_ERROR));
        }
    }
}

#[cfg(not(feature = "wasm"))]
impl P512SigningKey {
    /// Create Signing key from pem formatted private key. <b>pkcs8</b> and <b>pkcs1</b>.
    pub fn from_pem(key_str: &str) -> Result<Self, Error> {
        let ec_key = match get_private_key_from_pem(key_str) {
            Ok(val) => val,
            Err(error) => return Err(error),
        };

        Ok(P512SigningKey { key: ec_key })
    }

    /// Create Signing key from private key bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let ec_key = match get_private_key_from_bytes(bytes) {
            Ok(val) => val,
            Err(error) => return Err(error),
        };

        Ok(P512SigningKey { key: ec_key })
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl P512SigningKey {
    /// Create Signing key from pem formatted private key. <b>pkcs8</b> and <b>pkcs1</b>.
    #[wasm_bindgen(js_name = "fromPem")]
    pub fn from_pem(key_str: &str) -> P512SigningKey {
        P512SigningKey {
            key_str: Some(String::from(key_str)),
            key_bytes: None,
        }
    }

    /// Create Signing key from private key bytes.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &[u8]) -> P512SigningKey {
        P512SigningKey {
            key_str: None,
            key_bytes: Some(bytes.to_vec()),
        }
    }

    fn get_key(&self) -> Result<SigningKey, Error> {
        let key_bytes = self.key_bytes.clone();
        let key_str = self.key_str.clone();

        if key_str.is_some() {
            get_private_key_from_pem(key_str.unwrap().as_str())
        } else if key_bytes.is_some() {
            get_private_key_from_bytes(key_bytes.unwrap().as_mut_slice())
        } else {
            Err(Error::new(crate::errors::PUBLIC_KEY_IDENTIFICATION_ERROR))
        }
    }

    pub fn from_js_object(value: Object) -> Result<P512SigningKey, Error> {
        let pem_field = JsValue::from_str("pem");

        if value.has_own_property(&pem_field) {
            let pem = match js_sys::Reflect::get(&value, &pem_field) {
                Ok(val) => {
                    let string_value = match val.as_string() {
                        Some(v) => v,
                        None => return Err(Error::new(crate::errors::MISSING_FIELD)),
                    };
                    string_value
                }
                Err(error) => {
                    fi_common::logger::error(error.as_string().unwrap().as_str());
                    return Err(Error::new(crate::errors::MISSING_FIELD));
                }
            };

            return Ok(P512SigningKey::from_pem(pem.as_str()));
        } else if value.is_array() {
            let arr = Uint8Array::new(&value).to_vec();
            let bytes = arr.as_slice();

            return Ok(P512SigningKey::from_bytes(bytes));
        } else {
            Err(Error::new(crate::errors::MISSING_FIELD))
        }
    }
}

/// Verifying key for [`crate::algorithms::Algorithm::ES512`]
#[wasm_bindgen]
pub struct P512VerifyingKey {
    #[cfg(not(feature = "wasm"))]
    key: VerifyingKey,

    #[cfg(feature = "wasm")]
    key_str: Option<String>,
    #[cfg(feature = "wasm")]
    key_bytes: Option<Vec<u8>>,
}

impl VerifyFromKey for P512VerifyingKey {
    fn verify(&self, content: String, signature: String, _alg: Algorithm) -> Result<bool, Error> {
        let decoded_sig = match base64_url::decode(signature.as_bytes()) {
            Ok(val) => val,
            Err(error) => {
                fi_common::logger::error(error.to_string().as_str());
                return Err(Error::new(crate::errors::DECODING_ERROR));
            }
        };

        let sig = match Signature::from_slice(&decoded_sig) {
            Ok(val) => val,
            Err(error) => {
                fi_common::logger::error(error.to_string().as_str());
                return Err(Error::new(crate::errors::SIGNATURE_IDENTIFICATION_FAILED));
            }
        };

        #[cfg(not(feature = "wasm"))]
        let key = &self.key;

        #[cfg(feature = "wasm")]
        let key = match self.get_key() {
            Ok(val) => val,
            Err(error) => return Err(error),
        };

        let verify_result: Result<(), p521::ecdsa::Error> = key.verify(content.as_bytes(), &sig);
        if verify_result.is_ok() {
            return Ok(true);
        } else {
            match verify_result.err() {
                Some(error) => {
                    fi_common::logger::error(error.to_string().as_str());
                }
                None => {}
            };
            return Ok(false);
        }
    }
}

fn get_public_key_from_pem(key_str: &str) -> Result<VerifyingKey, Error> {
    let key_scalar: elliptic_curve::PublicKey<NistP521> =
        match elliptic_curve::PublicKey::from_public_key_pem(key_str) {
            Ok(val) => val,
            Err(error) => {
                fi_common::logger::error(error.to_string().as_str());
                return Err(Error::new(crate::errors::EC_PEM_ERROR));
            }
        };
    match VerifyingKey::from_sec1_bytes(&key_scalar.to_sec1_bytes()) {
        Ok(val) => Ok(val),
        Err(error) => {
            fi_common::logger::error(error.to_string().as_str());
            return Err(Error::new(crate::errors::PUBLIC_KEY_IDENTIFICATION_ERROR));
        }
    }
}

fn get_public_key_from_bytes(bytes: &[u8]) -> Result<VerifyingKey, Error> {
    match VerifyingKey::from_sec1_bytes(bytes) {
        Ok(val) => Ok(val),
        Err(error) => {
            fi_common::logger::error(error.to_string().as_str());
            return Err(Error::new(crate::errors::PUBLIC_KEY_IDENTIFICATION_ERROR));
        }
    }
}

#[cfg(not(feature = "wasm"))]
impl P512VerifyingKey {
    /// Create verifying key from pem formated key. <b>pkcs8</b> only.
    pub fn from_pem(key_str: &str) -> Result<P512VerifyingKey, Error> {
        let ec_key = match get_public_key_from_pem(key_str) {
            Ok(val) => val,
            Err(error) => return Err(error),
        };

        Ok(P512VerifyingKey { key: ec_key })
    }

    /// Create verifying key from key bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<P512VerifyingKey, Error> {
        let ec_key = match get_public_key_from_bytes(bytes) {
            Ok(val) => val,
            Err(error) => return Err(error),
        };

        Ok(P512VerifyingKey { key: ec_key })
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl P512VerifyingKey {
    /// Create verifying key from pem formated key. <b>pkcs8</b> only.
    #[wasm_bindgen(js_name = "fromPem")]
    pub fn from_pem(key_str: &str) -> P512VerifyingKey {
        P512VerifyingKey {
            key_str: Some(String::from(key_str)),
            key_bytes: None,
        }
    }

    /// Create verifying key from key bytes.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &[u8]) -> P512VerifyingKey {
        P512VerifyingKey {
            key_str: None,
            key_bytes: Some(bytes.to_vec()),
        }
    }

    fn get_key(&self) -> Result<VerifyingKey, Error> {
        let key_bytes = self.key_bytes.clone();
        let key_str = self.key_str.clone();

        if key_str.is_some() {
            get_public_key_from_pem(key_str.unwrap().as_str())
        } else if key_bytes.is_some() {
            get_public_key_from_bytes(key_bytes.unwrap().as_mut_slice())
        } else {
            Err(Error::new(crate::errors::PUBLIC_KEY_IDENTIFICATION_ERROR))
        }
    }

    pub fn from_js_object(value: Object) -> Result<P512VerifyingKey, Error> {
        let pem_field = JsValue::from_str("pem");
        if value.has_own_property(&pem_field) {
            let pem = match js_sys::Reflect::get(&value, &pem_field) {
                Ok(val) => {
                    let string_value = match val.as_string() {
                        Some(v) => v,
                        None => return Err(Error::new(crate::errors::MISSING_FIELD)),
                    };
                    string_value
                }
                Err(error) => {
                    fi_common::logger::error(error.as_string().unwrap().as_str());
                    return Err(Error::new(crate::errors::MISSING_FIELD));
                }
            };

            return Ok(P512VerifyingKey::from_pem(pem.as_str()));
        } else if value.is_array() {
            let arr = Uint8Array::new(&value).to_vec();
            let bytes = arr.as_slice();

            return Ok(P512VerifyingKey::from_bytes(bytes));
        } else {
            Err(Error::new(crate::errors::MISSING_FIELD))
        }
    }
}

/// Sign content using [`crate::algorithms::Algorithm::ES512`] algorithm
#[cfg(not(feature = "wasm"))]
pub fn ec_512_sign(message: String, key: impl SignFromKey) -> Result<String, Error> {
    key.sign(message, Algorithm::ES512)
}

#[cfg(feature = "wasm")]
pub fn ec_512_sign(message: String, key: impl SignFromKey) -> Result<String, Error> {
    match key.sign(message, Algorithm::ES512) {
        Ok(val) => Ok(val),
        Err(error) => Err(error),
    }
}

/// Verify signature using [`crate::algorithms::Algorithm::ES512`] algorithm
#[cfg(not(feature = "wasm"))]
pub fn ec_512_verify(message: String, sig: String, key: impl VerifyFromKey) -> Result<bool, Error> {
    key.verify(message, sig, Algorithm::ES512)
}

#[cfg(feature = "wasm")]
pub fn ec_512_verify(message: String, sig: String, key: impl VerifyFromKey) -> Result<bool, Error> {
    match key.verify(message, sig, Algorithm::ES512) {
        Ok(val) => Ok(val),
        Err(error) => Err(error),
    }
}
