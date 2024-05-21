use std::str::FromStr;

use crate::{
    algorithms::Algorithm,
    crypto::{SignFromKey, VerifyFromKey},
    errors::Error,
    log,
};
use elliptic_curve::pkcs8::DecodePublicKey;
#[cfg(feature = "wasm")]
use js_sys::{Object, Uint8Array};
use k256::{
    ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey},
    Secp256k1,
};
use wasm_bindgen::prelude::wasm_bindgen;
#[cfg(feature = "wasm")]
use wasm_bindgen::JsValue;

/// Signing key for [`crate::algorithms::Algorithm::ES256K`]
#[wasm_bindgen]
pub struct P256kSigningKey {
    #[cfg(not(feature = "wasm"))]
    key: SigningKey,

    #[cfg(feature = "wasm")]
    key_str: Option<String>,
    #[cfg(feature = "wasm")]
    key_bytes: Option<Vec<u8>>,
}

impl SignFromKey for P256kSigningKey {
    fn sign(&self, content: String, _alg: Algorithm) -> Result<String, Error> {
        #[cfg(not(feature = "wasm"))]
        let key = &self.key;

        #[cfg(feature = "wasm")]
        let key = match self.get_key() {
            Ok(val) => val,
            Err(error) => return Err(error),
        };

        let sig_result: Result<Signature, k256::ecdsa::Error> = key.try_sign(content.as_bytes());
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

fn get_private_key_from_pem(key_str: &str) -> Result<SigningKey, Error> {
    match key_str.starts_with("-----BEGIN EC PRIVATE KEY-----") {
        true => {
            let key_scalar: elliptic_curve::SecretKey<Secp256k1> =
                match elliptic_curve::SecretKey::from_sec1_pem(key_str) {
                    Ok(val) => val,
                    Err(error) => {
                        log::error(error.to_string().as_str());
                        return Err(Error::EC_PEM_ERROR);
                    }
                };

            match SigningKey::from_bytes(&key_scalar.as_scalar_primitive().to_bytes()) {
                Ok(val) => Ok(val),
                Err(error) => {
                    log::error(error.to_string().as_str());
                    return Err(Error::PRIVATE_KEY_IDENTIFICATION_ERROR);
                }
            }
        }
        false => {
            let key_scalar: elliptic_curve::SecretKey<Secp256k1> =
                match elliptic_curve::SecretKey::from_str(key_str) {
                    Ok(val) => val,
                    Err(error) => {
                        log::error(error.to_string().as_str());
                        return Err(Error::EC_PEM_ERROR);
                    }
                };

            match SigningKey::from_bytes(&key_scalar.as_scalar_primitive().to_bytes()) {
                Ok(val) => Ok(val),
                Err(error) => {
                    log::error(error.to_string().as_str());
                    return Err(Error::PRIVATE_KEY_IDENTIFICATION_ERROR);
                }
            }
        }
    }
}

fn get_private_key_from_bytes(bytes: &[u8]) -> Result<SigningKey, Error> {
    match SigningKey::from_slice(bytes) {
        Ok(val) => Ok(val),
        Err(error) => {
            log::error(error.to_string().as_str());
            return Err(Error::PUBLIC_KEY_IDENTIFICATION_ERROR);
        }
    }
}

#[cfg(not(feature = "wasm"))]
impl P256kSigningKey {
    /// Create Signing key from pem formatted private key. <b>pkcs8</b> and <b>pkcs1</b>.
    pub fn from_pem(key_str: &str) -> Result<P256kSigningKey, Error> {
        let ec_key = match get_private_key_from_pem(key_str) {
            Ok(val) => val,
            Err(error) => return Err(error),
        };

        Ok(P256kSigningKey { key: ec_key })
    }

    /// Create Signing key from private key bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<P256kSigningKey, Error> {
        let ec_key = match get_private_key_from_bytes(bytes) {
            Ok(val) => val,
            Err(error) => return Err(error),
        };

        Ok(P256kSigningKey { key: ec_key })
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl P256kSigningKey {
    /// Create Signing key from pem formatted private key. <b>pkcs8</b> and <b>pkcs1</b>.
    #[wasm_bindgen(js_name = "fromPem")]
    pub fn from_pem(key_str: &str) -> P256kSigningKey {
        P256kSigningKey {
            key_str: Some(String::from(key_str)),
            key_bytes: None,
        }
    }

    /// Create Signing key from private key bytes.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &[u8]) -> P256kSigningKey {
        P256kSigningKey {
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
            Err(Error::PRIVATE_KEY_IDENTIFICATION_ERROR)
        }
    }

    pub fn from_js_object(value: Object) -> Result<P256kSigningKey, Error> {
        let pem_field = JsValue::from_str("pem");

        if value.has_own_property(&pem_field) {
            let pem = match js_sys::Reflect::get(&value, &pem_field) {
                Ok(val) => {
                    let string_value = match val.as_string() {
                        Some(v) => v,
                        None => return Err(Error::MISSING_FIELD),
                    };
                    string_value
                }
                Err(error) => {
                    log::error(error.as_string().unwrap().as_str());
                    return Err(Error::MISSING_FIELD);
                }
            };

            return Ok(P256kSigningKey::from_pem(pem.as_str()));
        } else if value.is_array() {
            let arr = Uint8Array::new(&value).to_vec();
            let bytes = arr.as_slice();

            return Ok(P256kSigningKey::from_bytes(bytes));
        } else {
            Err(Error::MISSING_FIELD)
        }
    }
}

/// Verifying key for [`crate::algorithms::Algorithm::ES256K`]
#[wasm_bindgen]
pub struct P256kVerifyingKey {
    #[cfg(not(feature = "wasm"))]
    key: VerifyingKey,

    #[cfg(feature = "wasm")]
    key_str: Option<String>,
    #[cfg(feature = "wasm")]
    key_bytes: Option<Vec<u8>>,
}

impl VerifyFromKey for P256kVerifyingKey {
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

        #[cfg(not(feature = "wasm"))]
        let key = &self.key;

        #[cfg(feature = "wasm")]
        let key = match self.get_key() {
            Ok(val) => val,
            Err(error) => return Err(error),
        };

        let verify_result: Result<(), k256::ecdsa::Error> = key.verify(content.as_bytes(), &sig);
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

fn get_public_key_from_pem(key_str: &str) -> Result<VerifyingKey, Error> {
    let key_scalar: elliptic_curve::PublicKey<Secp256k1> =
        match elliptic_curve::PublicKey::from_public_key_pem(key_str) {
            Ok(val) => val,
            Err(error) => {
                log::error(error.to_string().as_str());
                return Err(Error::EC_PEM_ERROR);
            }
        };
    match VerifyingKey::from_sec1_bytes(&key_scalar.to_sec1_bytes()) {
        Ok(val) => Ok(val),
        Err(error) => {
            log::error(error.to_string().as_str());
            return Err(Error::PUBLIC_KEY_IDENTIFICATION_ERROR);
        }
    }
}

fn get_public_key_from_bytes(bytes: &[u8]) -> Result<VerifyingKey, Error> {
    match VerifyingKey::from_sec1_bytes(bytes) {
        Ok(val) => Ok(val),
        Err(error) => {
            log::error(error.to_string().as_str());
            return Err(Error::PUBLIC_KEY_IDENTIFICATION_ERROR);
        }
    }
}

#[cfg(not(feature = "wasm"))]
impl P256kVerifyingKey {
    /// Create verifying key from pem formated key. <b>pkcs8</b> only.
    pub fn from_pem(key_str: &str) -> Result<P256kVerifyingKey, Error> {
        let ec_key = match get_public_key_from_pem(key_str) {
            Ok(val) => val,
            Err(error) => return Err(error),
        };

        Ok(P256kVerifyingKey { key: ec_key })
    }

    /// Create verifying key from key bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<P256kVerifyingKey, Error> {
        let ec_key = match get_public_key_from_bytes(bytes) {
            Ok(val) => val,
            Err(error) => return Err(error),
        };

        Ok(P256kVerifyingKey { key: ec_key })
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl P256kVerifyingKey {
    /// Create verifying key from pem formated key. <b>pkcs8</b> only.
    #[wasm_bindgen(js_name = "fromPem")]
    pub fn from_pem(key_str: &str) -> P256kVerifyingKey {
        P256kVerifyingKey {
            key_str: Some(String::from(key_str)),
            key_bytes: None,
        }
    }

    /// Create verifying key from key bytes.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &[u8]) -> P256kVerifyingKey {
        P256kVerifyingKey {
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
            Err(Error::PUBLIC_KEY_IDENTIFICATION_ERROR)
        }
    }

    pub fn from_js_object(value: Object) -> Result<P256kVerifyingKey, Error> {
        let pem_field = JsValue::from_str("pem");
        if value.has_own_property(&pem_field) {
            let pem = match js_sys::Reflect::get(&value, &pem_field) {
                Ok(val) => {
                    let string_value = match val.as_string() {
                        Some(v) => v,
                        None => return Err(Error::MISSING_FIELD),
                    };
                    string_value
                }
                Err(error) => {
                    log::error(error.as_string().unwrap().as_str());
                    return Err(Error::MISSING_FIELD);
                }
            };

            return Ok(P256kVerifyingKey::from_pem(pem.as_str()));
        } else if value.is_array() {
            let arr = Uint8Array::new(&value).to_vec();
            let bytes = arr.as_slice();

            return Ok(P256kVerifyingKey::from_bytes(bytes));
        } else {
            Err(Error::MISSING_FIELD)
        }
    }
}

/// Sign content using [`crate::algorithms::Algorithm::ES256K`] algorithm
#[cfg(not(feature = "wasm"))]
pub fn ec_256k_sign(message: String, key: impl SignFromKey) -> Result<String, Error> {
    key.sign(message, Algorithm::ES256K)
}

#[cfg(feature = "wasm")]
pub fn ec_256k_sign(message: String, key: impl SignFromKey) -> Result<String, String> {
    match key.sign(message, Algorithm::ES256K) {
        Ok(val) => Ok(val),
        Err(error) => Err(error.to_string()),
    }
}

/// Verify signature using [`crate::algorithms::Algorithm::ES256K`] algorithm
#[cfg(not(feature = "wasm"))]
pub fn ec_256k_verify(
    message: String,
    sig: String,
    key: impl VerifyFromKey,
) -> Result<bool, Error> {
    key.verify(message, sig, Algorithm::ES256K)
}

#[cfg(feature = "wasm")]
pub fn ec_256k_verify(
    message: String,
    sig: String,
    key: impl VerifyFromKey,
) -> Result<bool, String> {
    match key.verify(message, sig, Algorithm::ES256K) {
        Ok(val) => Ok(val),
        Err(error) => Err(error.to_string()),
    }
}
