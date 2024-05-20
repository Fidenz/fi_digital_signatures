use crate::{
    algorithms::Algorithm, crypto::SignFromKey, crypto::VerifyFromKey, errors::Error, log,
};
#[cfg(feature = "wasm")]
use js_sys::Object;
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use rsa::pkcs1v15::Signature;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::sha2::{Sha256, Sha384, Sha512};
use rsa::signature::{RandomizedSigner, SignatureEncoding, SignerMut, Verifier};
use rsa::BigUint;
#[cfg(feature = "wasm")]
use std::str::FromStr;
use wasm_bindgen::prelude::wasm_bindgen;
#[cfg(feature = "wasm")]
use wasm_bindgen::JsValue;

/// Signing key for RSA based algorithms (RSA private key)
#[derive(Debug)]
#[wasm_bindgen]
pub struct RsaSigningKey {
    #[cfg(not(feature = "wasm"))]
    key: rsa::RsaPrivateKey,

    #[cfg(feature = "wasm")]
    key_str: Option<String>,
    #[cfg(feature = "wasm")]
    key_components: Option<[String; 5]>,
}

fn get_rsa_private_key_from_pem(key_str: &str) -> Result<rsa::RsaPrivateKey, Error> {
    match key_str.starts_with("-----BEGIN RSA PRIVATE KEY-----") {
        true => match rsa::RsaPrivateKey::from_pkcs1_pem(key_str) {
            Ok(val) => Ok(val),
            Err(error) => {
                log::error(error.to_string().as_str());
                return Err(Error::PRIVATE_KEY_IDENTIFICATION_ERROR);
            }
        },
        false => match rsa::RsaPrivateKey::from_pkcs8_pem(key_str) {
            Ok(val) => Ok(val),
            Err(error) => {
                log::error(error.to_string().as_str());
                return Err(Error::PRIVATE_KEY_IDENTIFICATION_ERROR);
            }
        },
    }
}

fn get_rsa_private_key_from_components(
    n: BigUint,
    e: BigUint,
    d: BigUint,
    p: BigUint,
    q: BigUint,
) -> Result<rsa::RsaPrivateKey, Error> {
    match rsa::RsaPrivateKey::from_components(n, e, d, vec![p, q]) {
        Ok(val) => Ok(val),
        Err(error) => {
            log::error(error.to_string().as_str());
            return Err(Error::PRIVATE_KEY_IDENTIFICATION_ERROR);
        }
    }
}

#[cfg(not(feature = "wasm"))]
impl RsaSigningKey {
    /// Import <b>RsaSigningKey</b> from pem private key.
    /// Both <b>pkcs8</b> and <b>pkcs1</b> works.
    #[cfg(not(feature = "wasm"))]
    pub fn from_pem(key_str: &str) -> Result<RsaSigningKey, Error> {
        let rsa_key = match get_rsa_private_key_from_pem(key_str) {
            Ok(val) => val,
            Err(error) => return Err(error),
        };

        Ok(RsaSigningKey { key: rsa_key })
    }

    // Import <b>RsaSigningKey</b> from RSA private key components
    #[cfg(not(feature = "wasm"))]
    pub fn from_components(
        n: BigUint,
        e: BigUint,
        d: BigUint,
        p: BigUint,
        q: BigUint,
    ) -> Result<RsaSigningKey, Error> {
        let rsa_key = match get_rsa_private_key_from_components(n, e, d, p, q) {
            Ok(val) => val,
            Err(error) => return Err(error),
        };

        Ok(RsaSigningKey { key: rsa_key })
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl RsaSigningKey {
    /// Import <b>RsaSigningKey</b> from pem private key.
    /// Both <b>pkcs8</b> and <b>pkcs1</b> works.
    #[wasm_bindgen(js_name = "fromPem")]
    pub fn from_pem(key_str: &str) -> RsaSigningKey {
        RsaSigningKey {
            key_str: Some(String::from(key_str)),
            key_components: None,
        }
    }

    // Import <b>RsaSigningKey</b> from RSA private key components
    #[wasm_bindgen]
    pub fn from_components(n: String, e: String, d: String, p: String, q: String) -> RsaSigningKey {
        RsaSigningKey {
            key_str: None,
            key_components: Some([n, e, d, p, q]),
        }
    }

    fn get_key(&self) -> Result<rsa::RsaPrivateKey, Error> {
        let components_res = self.key_components.clone();
        let key_str = self.key_str.clone();

        if key_str.is_some() {
            get_rsa_private_key_from_pem(key_str.unwrap().as_str())
        } else if components_res.is_some() {
            let components = components_res.unwrap();
            get_rsa_private_key_from_components(
                BigUint::from_str(components[0].as_str()).unwrap(),
                BigUint::from_str(components[1].as_str()).unwrap(),
                BigUint::from_str(components[2].as_str()).unwrap(),
                BigUint::from_str(components[3].as_str()).unwrap(),
                BigUint::from_str(components[4].as_str()).unwrap(),
            )
        } else {
            Err(Error::PRIVATE_KEY_IDENTIFICATION_ERROR)
        }
    }

    pub fn from_js_object(value: Object) -> Result<RsaSigningKey, Error> {
        let pem_field = JsValue::from_str("pem");
        let n_field = JsValue::from_str("pem");
        let e_field = JsValue::from_str("pem");
        let d_field = JsValue::from_str("pem");
        let p_field = JsValue::from_str("pem");
        let q_field = JsValue::from_str("pem");

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

            return Ok(RsaSigningKey::from_pem(pem.as_str()));
        } else if value.has_own_property(&n_field)
            && value.has_own_property(&e_field)
            && value.has_own_property(&d_field)
            && value.has_own_property(&p_field)
            && value.has_own_property(&q_field)
        {
            let n = match js_sys::Reflect::get(&value, &n_field) {
                Ok(val) => val.as_string().unwrap(),
                Err(error) => {
                    log::error(error.as_string().unwrap().as_str());
                    return Err(Error::MISSING_FIELD);
                }
            };

            let e = match js_sys::Reflect::get(&value, &e_field) {
                Ok(val) => val.as_string().unwrap(),
                Err(error) => {
                    log::error(error.as_string().unwrap().as_str());
                    return Err(Error::MISSING_FIELD);
                }
            };

            let d = match js_sys::Reflect::get(&value, &d_field) {
                Ok(val) => val.as_string().unwrap(),
                Err(error) => {
                    log::error(error.as_string().unwrap().as_str());
                    return Err(Error::MISSING_FIELD);
                }
            };

            let p = match js_sys::Reflect::get(&value, &p_field) {
                Ok(val) => val.as_string().unwrap(),
                Err(error) => {
                    log::error(error.as_string().unwrap().as_str());
                    return Err(Error::MISSING_FIELD);
                }
            };

            let q = match js_sys::Reflect::get(&value, &q_field) {
                Ok(val) => val.as_string().unwrap(),
                Err(error) => {
                    log::error(error.as_string().unwrap().as_str());
                    return Err(Error::MISSING_FIELD);
                }
            };

            return Ok(RsaSigningKey::from_components(n, e, d, p, q));
        } else {
            Err(Error::MISSING_FIELD)
        }
    }
}

impl SignFromKey for RsaSigningKey {
    fn sign(&self, message: String, alg: Algorithm) -> Result<String, Error> {
        #[cfg(not(feature = "wasm"))]
        let key = self.key.clone();

        #[cfg(feature = "wasm")]
        let key = match self.get_key() {
            Ok(val) => val,
            Err(error) => return Err(error),
        };

        let mut rng = rand::thread_rng();
        if alg.to_str().starts_with("RS") {
            let sig: Signature = match alg {
                Algorithm::RS256 => {
                    let mut signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(key);
                    signing_key.sign(message.as_bytes())
                }
                Algorithm::RS384 => {
                    let mut signing_key = rsa::pkcs1v15::SigningKey::<Sha384>::new(key);
                    signing_key.sign(message.as_bytes())
                }
                Algorithm::RS512 => {
                    let mut signing_key = rsa::pkcs1v15::SigningKey::<Sha512>::new(key);
                    signing_key.sign(message.as_bytes())
                }
                _ => return Err(Error::UNKNOWN_ALGORITHM),
            };
            let bytes = sig.to_bytes();
            Ok(base64_url::encode(&bytes))
        } else {
            let sig = match alg {
                Algorithm::PS256 => {
                    let signing_key = rsa::pss::SigningKey::<Sha256>::new(key);
                    signing_key.sign_with_rng(&mut rng, message.as_bytes())
                }
                Algorithm::PS384 => {
                    let signing_key = rsa::pss::SigningKey::<Sha384>::new(key);
                    signing_key.sign_with_rng(&mut rng, message.as_bytes())
                }
                Algorithm::PS512 => {
                    let signing_key = rsa::pss::SigningKey::<Sha512>::new(key);
                    signing_key.sign_with_rng(&mut rng, message.as_bytes())
                }
                _ => return Err(Error::UNKNOWN_ALGORITHM),
            };

            let bytes = sig.to_bytes();
            Ok(base64_url::encode(&bytes))
        }
    }
}

/// Verifying key for RSA based algorithms (RSA private key)
#[derive(Debug)]
#[wasm_bindgen]
pub struct RsaVerifyingKey {
    #[cfg(not(feature = "wasm"))]
    key: rsa::RsaPublicKey,
    #[cfg(feature = "wasm")]
    key_str: String,
}

fn get_public_key_from_pem(key_str: &str) -> Result<rsa::RsaPublicKey, Error> {
    match key_str.starts_with("-----BEGIN RSA PUBLIC KEY-----") {
        true => match rsa::RsaPublicKey::from_pkcs1_pem(key_str) {
            Ok(val) => Ok(val),
            Err(error) => {
                log::error(error.to_string().as_str());
                return Err(Error::PRIVATE_KEY_IDENTIFICATION_ERROR);
            }
        },
        false => match rsa::RsaPublicKey::from_public_key_pem(key_str) {
            Ok(val) => Ok(val),
            Err(error) => {
                log::error(error.to_string().as_str());
                return Err(Error::PRIVATE_KEY_IDENTIFICATION_ERROR);
            }
        },
    }
}

#[cfg(not(feature = "wasm"))]
impl RsaVerifyingKey {
    /// Import <b>RsaSigningKey</b> from pem private key.
    /// Both <b>pkcs8</b> and <b>pkcs1</b> works.
    pub fn from_pem(key_str: &str) -> Result<RsaVerifyingKey, Error> {
        let rsa_key = match get_public_key_from_pem(key_str) {
            Ok(val) => val,
            Err(error) => return Err(error),
        };

        Ok(RsaVerifyingKey { key: rsa_key })
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl RsaVerifyingKey {
    /// Import <b>RsaSigningKey</b> from pem private key.
    /// Both <b>pkcs8</b> and <b>pkcs1</b> works.
    #[wasm_bindgen]
    pub fn from_pem(key_str: &str) -> RsaVerifyingKey {
        RsaVerifyingKey {
            key_str: String::from(key_str),
        }
    }

    pub fn from_js_object(value: Object) -> Result<RsaVerifyingKey, Error> {
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

            Ok(RsaVerifyingKey::from_pem(pem.as_str()))
        } else {
            Err(Error::MISSING_FIELD)
        }
    }
}

impl VerifyFromKey for RsaVerifyingKey {
    fn verify(&self, message: String, signature: String, alg: Algorithm) -> Result<bool, Error> {
        #[cfg(not(feature = "wasm"))]
        let key = self.key.clone();

        #[cfg(feature = "wasm")]
        let key = match get_public_key_from_pem(self.key_str.as_str()) {
            Ok(val) => val,
            Err(error) => return Err(error),
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
                    let verifying_key = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(key);
                    verifying_key.verify(message.as_bytes(), &sig)
                }
                Algorithm::RS384 => {
                    let verifying_key = rsa::pkcs1v15::VerifyingKey::<Sha384>::new(key);
                    verifying_key.verify(message.as_bytes(), &sig)
                }
                Algorithm::RS512 => {
                    let verifying_key = rsa::pkcs1v15::VerifyingKey::<Sha512>::new(key);
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
                Algorithm::PS256 => {
                    let verifying_key = rsa::pss::VerifyingKey::<Sha256>::new(key);
                    verifying_key.verify(message.as_bytes(), &sig)
                }
                Algorithm::PS384 => {
                    let verifying_key = rsa::pss::VerifyingKey::<Sha384>::new(key);
                    verifying_key.verify(message.as_bytes(), &sig)
                }
                Algorithm::PS512 => {
                    let verifying_key = rsa::pss::VerifyingKey::<Sha512>::new(key);
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
}

/// Sign the content with the provided key and algorithm
pub fn sign_rsa(message: String, key: impl SignFromKey, alg: Algorithm) -> Result<String, Error> {
    key.sign(message, alg)
}

/// Verify the signature with the provided key and algorithm
pub fn verify_rsa(
    message: String,
    signature: String,
    key: impl VerifyFromKey,
    alg: Algorithm,
) -> Result<bool, Error> {
    key.verify(message, signature, alg)
}
