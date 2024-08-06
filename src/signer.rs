use crate::{
    algorithms::{Algorithm, AlgorithmFamily},
    crypto::{
        ecdsa::{
            _256k::P256kSigningKey, sign_ec, _256::P256SigningKey, _384::P384SigningKey,
            _512::P512SigningKey,
        },
        eddsa::{sign_eddsa, EDDSASigningKey},
        hmac::sign_hmac,
        rsa::{sign_rsa, RsaSigningKey},
    },
    errors::Error,
};

#[cfg(not(feature = "wasm"))]
use crate::crypto::SignFromKey;
#[cfg(feature = "wasm")]
use crate::crypto::{eddsa::EDDSASigningKey, hmac::HMACKey, rsa::RsaSigningKey};
#[cfg(feature = "wasm")]
use js_sys::Object;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

/// Signs the content with a provided Key
#[cfg(not(feature = "wasm"))]
pub fn sign(message: String, key: impl SignFromKey, alg: Algorithm) -> Result<String, Error> {
    let alg_family = alg.get_family();
    match alg_family {
        AlgorithmFamily::HMAC => sign_hmac(message, key, alg),
        AlgorithmFamily::RSA => sign_rsa(message, key, alg),
        AlgorithmFamily::EC => sign_ec(message, key, alg),
        AlgorithmFamily::OKP => sign_eddsa(message, key, alg),
        _ => return Err(Error::UNKNOWN_ALGORITHM),
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn sign(message: String, key: Object, alg: Algorithm) -> Result<String, String> {
    let alg_family = alg.get_family();
    match alg_family {
        AlgorithmFamily::HMAC => sign_hmac(
            message,
            match HMACKey::from_js_object(key) {
                Ok(val) => val,
                Err(error) => return Err(error.to_string()),
            },
            alg,
        ),
        AlgorithmFamily::RSA => sign_rsa(
            message,
            match RsaSigningKey::from_js_object(key) {
                Ok(val) => val,
                Err(error) => return Err(error.to_string()),
            },
            alg,
        ),
        AlgorithmFamily::EC => sign_ec(message, key, alg),
        AlgorithmFamily::OKP => sign_eddsa(
            message,
            match EDDSASigningKey::from_js_object(key) {
                Ok(val) => val,
                Err(error) => return Err(error.to_string()),
            },
            alg,
        ),
        _ => return Err(Error::UNKNOWN_ALGORITHM.to_string()),
    }
}

pub fn get_signing_key(
    alg: Algorithm,
    key_bytes: &mut [u8],
) -> Result<Box<dyn SignFromKey>, Error> {
    match alg {
        Algorithm::ES256 => match P256SigningKey::from_bytes(key_bytes) {
            Ok(val) => return Ok(Box::new(val)),
            Err(error) => return Err(error),
        },
        Algorithm::ES256K => match P256kSigningKey::from_bytes(key_bytes) {
            Ok(val) => return Ok(Box::new(val)),
            Err(error) => return Err(error),
        },
        Algorithm::ES384 => match P384SigningKey::from_bytes(key_bytes) {
            Ok(val) => return Ok(Box::new(val)),
            Err(error) => return Err(error),
        },
        Algorithm::ES512 => match P512SigningKey::from_bytes(key_bytes) {
            Ok(val) => return Ok(Box::new(val)),
            Err(error) => return Err(error),
        },
        Algorithm::RS256 => match RsaSigningKey::from_bytes(key_bytes) {
            Ok(val) => return Ok(Box::new(val)),
            Err(error) => return Err(error),
        },
        Algorithm::RS384 => match RsaSigningKey::from_bytes(key_bytes) {
            Ok(val) => return Ok(Box::new(val)),
            Err(error) => return Err(error),
        },
        Algorithm::RS512 => match RsaSigningKey::from_bytes(key_bytes) {
            Ok(val) => return Ok(Box::new(val)),
            Err(error) => return Err(error),
        },
        Algorithm::PS256 => match RsaSigningKey::from_bytes(key_bytes) {
            Ok(val) => return Ok(Box::new(val)),
            Err(error) => return Err(error),
        },
        Algorithm::PS384 => match RsaSigningKey::from_bytes(key_bytes) {
            Ok(val) => return Ok(Box::new(val)),
            Err(error) => return Err(error),
        },
        Algorithm::PS512 => match RsaSigningKey::from_bytes(key_bytes) {
            Ok(val) => return Ok(Box::new(val)),
            Err(error) => return Err(error),
        },
        Algorithm::HS256 => return Err(Error::NOT_USING_ASYMMETRIC_KEYS),
        Algorithm::HS384 => return Err(Error::NOT_USING_ASYMMETRIC_KEYS),
        Algorithm::HS512 => return Err(Error::NOT_USING_ASYMMETRIC_KEYS),
        Algorithm::EdDSA => match EDDSASigningKey::from_bytes(key_bytes) {
            Ok(val) => return Ok(Box::new(val)),
            Err(error) => return Err(error),
        },
    }
}
