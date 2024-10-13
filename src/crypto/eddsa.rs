use ed25519_dalek::{
    pkcs8::DecodePrivateKey, pkcs8::DecodePublicKey, Signer, SigningKey, Verifier,
};
use ed25519_dalek::{Signature, VerifyingKey};
#[cfg(feature = "wasm")]
use js_sys::{Object, Uint8Array};
#[cfg(feature = "wasm")]
use wasm_bindgen::JsValue;

use crate::algorithms::Algorithm;
use fi_common::error::Error;

use wasm_bindgen::prelude::wasm_bindgen;

use super::{SignFromKey, VerifyFromKey};

/// Signing key for ED25519 algorithm [`crate::algorithms::Algorithm::EdDSA`]
#[wasm_bindgen]
pub struct EDDSASigningKey {
    #[cfg(not(feature = "wasm"))]
    key: SigningKey,

    #[cfg(feature = "wasm")]
    key_str: Option<String>,
    #[cfg(feature = "wasm")]
    key_bytes: Option<Vec<u8>>,
}

impl SignFromKey for EDDSASigningKey {
    fn sign(&self, content: String, _alg: Algorithm) -> Result<String, Error> {
        #[cfg(not(feature = "wasm"))]
        let key = self.key.clone();

        #[cfg(feature = "wasm")]
        let key = match self.get_key() {
            Ok(val) => val,
            Err(error) => return Err(error),
        };

        let sig_result: Result<Signature, ed25519_dalek::ed25519::Error> =
            key.try_sign(content.as_bytes());
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

#[cfg(not(feature = "wasm"))]
impl EDDSASigningKey {
    /// Create signing key from pem formatted private key. <b>pksc8</b> only.
    pub fn from_pem(key_str: &str) -> Result<EDDSASigningKey, Error> {
        let pkc8_key = match get_private_key_from_pem(key_str) {
            Ok(val) => val,
            Err(error) => return Err(error),
        };

        Ok(EDDSASigningKey { key: pkc8_key })
    }

    /// Create signing key from private key bytes.
    pub fn from_bytes(bytes: &mut [u8]) -> Result<EDDSASigningKey, Error> {
        let ec_key = match get_private_key_from_bytes(bytes) {
            Ok(val) => val,
            Err(error) => return Err(error),
        };

        Ok(EDDSASigningKey { key: ec_key })
    }
}

fn get_private_key_from_pem(key_str: &str) -> Result<SigningKey, Error> {
    match SigningKey::from_pkcs8_pem(key_str) {
        Ok(val) => Ok(val),
        Err(error) => {
            fi_common::logger::error(error.to_string().as_str());
            return Err(Error::new(crate::errors::PRIVATE_KEY_IDENTIFICATION_ERROR));
        }
    }
}

fn get_private_key_from_bytes(bytes: &mut [u8]) -> Result<SigningKey, Error> {
    if bytes.len() != 32 {
        return Err(Error::new(crate::errors::PRIVATE_KEY_IDENTIFICATION_ERROR));
    }

    let mut ec_bytes: [u8; 32] = [0; 32];
    ec_bytes.copy_from_slice(&bytes);
    Ok(SigningKey::from_bytes(&ec_bytes))
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl EDDSASigningKey {
    /// Create signing key from pem formatted private key. <b>pksc8</b> only.
    #[wasm_bindgen]
    pub fn from_pem(key_str: &str) -> EDDSASigningKey {
        EDDSASigningKey {
            key_str: Some(String::from(key_str)),
            key_bytes: None,
        }
    }

    /// Create signing key from private key bytes.
    #[wasm_bindgen]
    pub fn from_bytes(bytes: &mut [u8]) -> EDDSASigningKey {
        EDDSASigningKey {
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
            Err(Error::new(crate::errors::PRIVATE_KEY_IDENTIFICATION_ERROR))
        }
    }

    pub fn from_js_object(value: Object) -> Result<EDDSASigningKey, Error> {
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

            return Ok(EDDSASigningKey::from_pem(pem.as_str()));
        } else if value.is_array() {
            let mut arr = Uint8Array::new(&value).to_vec();
            let bytes = arr.as_mut_slice();

            return Ok(EDDSASigningKey::from_bytes(bytes));
        } else {
            Err(Error::new(crate::errors::MISSING_FIELD))
        }
    }
}

/// Verifying key for ED25519 algorithm
#[wasm_bindgen]
pub struct EDDSAVerifyingKey {
    #[cfg(not(feature = "wasm"))]
    key: VerifyingKey,
    #[cfg(feature = "wasm")]
    key_bytes: Option<Vec<u8>>,
    #[cfg(feature = "wasm")]
    key_str: Option<String>,
}

impl VerifyFromKey for EDDSAVerifyingKey {
    fn verify(&self, content: String, sig: String, _alg: Algorithm) -> Result<bool, Error> {
        let decoded_sig = match base64_url::decode(sig.as_bytes()) {
            Ok(val) => val,
            Err(error) => {
                fi_common::logger::error(error.to_string().as_str());
                return Err(Error::new(crate::errors::DECODING_ERROR));
            }
        };

        let signature = match Signature::from_slice(&decoded_sig) {
            Ok(val) => val,
            Err(error) => {
                fi_common::logger::error(error.to_string().as_str());
                return Err(Error::new(crate::errors::SIGNATURE_IDENTIFICATION_FAILED));
            }
        };

        #[cfg(not(feature = "wasm"))]
        let key = self.key.clone();

        #[cfg(feature = "wasm")]
        let key = match self.get_key() {
            Ok(val) => val,
            Err(error) => return Err(error),
        };

        let verify_result: Result<(), ed25519_dalek::ed25519::Error> =
            key.verify(content.as_bytes(), &signature);
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
    match VerifyingKey::from_public_key_pem(key_str) {
        Ok(val) => Ok(val),
        Err(error) => {
            fi_common::logger::error(error.to_string().as_str());
            return Err(Error::new(crate::errors::PUBLIC_KEY_IDENTIFICATION_ERROR));
        }
    }
}

fn get_public_key_from_bytes(bytes: &mut [u8]) -> Result<VerifyingKey, Error> {
    if bytes.len() != 32 {
        return Err(Error::new(crate::errors::PUBLIC_KEY_IDENTIFICATION_ERROR));
    }

    let mut ec_bytes: [u8; 32] = [0; 32];
    ec_bytes.copy_from_slice(&bytes);
    match VerifyingKey::from_bytes(&ec_bytes) {
        Ok(val) => Ok(val),
        Err(error) => {
            fi_common::logger::error(error.to_string().as_str());
            return Err(Error::new(crate::errors::PUBLIC_KEY_IDENTIFICATION_ERROR));
        }
    }
}

#[cfg(not(feature = "wasm"))]
impl EDDSAVerifyingKey {
    /// Create verifying key from pem formatted public key. <b>pksc8</b> only.
    pub fn from_pem(key_str: &str) -> Result<EDDSAVerifyingKey, Error> {
        let pkc8_key = match get_public_key_from_pem(key_str) {
            Ok(val) => val,
            Err(error) => return Err(error),
        };

        Ok(EDDSAVerifyingKey { key: pkc8_key })
    }

    /// Create verifying key from public key bytes. <b>pksc8</b> only.
    pub fn from_bytes(bytes: &mut [u8]) -> Result<EDDSAVerifyingKey, Error> {
        let ec_key = match get_public_key_from_bytes(bytes) {
            Ok(val) => val,
            Err(error) => return Err(error),
        };
        Ok(EDDSAVerifyingKey { key: ec_key })
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl EDDSAVerifyingKey {
    /// Create verifying key from pem formatted public key. <b>pksc8</b> only.
    #[wasm_bindgen]
    pub fn from_pem(key_str: &str) -> EDDSAVerifyingKey {
        EDDSAVerifyingKey {
            key_str: Some(String::from(key_str)),
            key_bytes: None,
        }
    }

    /// Create verifying key from public key bytes. <b>pksc8</b> only.
    #[wasm_bindgen]
    pub fn from_bytes(bytes: &mut [u8]) -> EDDSAVerifyingKey {
        EDDSAVerifyingKey {
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

    pub fn from_js_object(value: Object) -> Result<EDDSAVerifyingKey, Error> {
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

            return Ok(EDDSAVerifyingKey::from_pem(pem.as_str()));
        } else if value.is_array() {
            let mut arr = Uint8Array::new(&value).to_vec();
            let bytes = arr.as_mut_slice();

            return Ok(EDDSAVerifyingKey::from_bytes(bytes));
        } else {
            Err(Error::new(crate::errors::MISSING_FIELD))
        }
    }
}

/// Sign content using [`crate::algorithms::Algorithm::EdDSA`] algorithm
#[cfg(not(feature = "wasm"))]
pub fn sign_eddsa(message: String, key: impl SignFromKey, alg: Algorithm) -> Result<String, Error> {
    key.sign(message, alg)
}

#[cfg(feature = "wasm")]
pub fn sign_eddsa(
    message: String,
    key: impl SignFromKey,
    alg: Algorithm,
) -> Result<String, String> {
    match key.sign(message, alg) {
        Ok(val) => Ok(val),
        Err(error) => Err(error.to_string()),
    }
}

/// Verify signature using [`crate::algorithms::Algorithm::EdDSA`] algorithm
#[cfg(not(feature = "wasm"))]
pub fn verify_eddsa(
    message: String,
    sig: String,
    key: impl VerifyFromKey,
    alg: Algorithm,
) -> Result<bool, Error> {
    key.verify(message, sig, alg)
}

#[cfg(feature = "wasm")]
pub fn verify_eddsa(
    message: String,
    sig: String,
    key: impl VerifyFromKey,
    alg: Algorithm,
) -> Result<bool, String> {
    match key.verify(message, sig, alg) {
        Ok(val) => Ok(val),
        Err(error) => Err(error.to_string()),
    }
}
