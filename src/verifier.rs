#[cfg(not(feature = "wasm"))]
use crate::crypto::VerifyFromKey;
#[cfg(feature = "wasm")]
use crate::crypto::{eddsa::EDDSAVerifyingKey, hmac::HMACKey, rsa::RsaVerifyingKey};
use crate::{
    algorithms::{Algorithm, AlgorithmFamily},
    crypto::{
        ecdsa::{
            _256k::P256kVerifyingKey, verify_ec, _256::P256VerifyingKey, _384::P384VerifyingKey,
            _512::P512VerifyingKey,
        },
        eddsa::{verify_eddsa, EDDSAVerifyingKey},
        hmac::verify_hmac,
        rsa::{verify_rsa, RsaVerifyingKey},
    },
};
use fi_common::error::Error;
#[cfg(feature = "wasm")]
use js_sys::Object;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

/// Verify the signature with a provided Key
#[cfg(not(feature = "wasm"))]
pub fn verify(
    message: String,
    signature: String,
    key: impl VerifyFromKey,
    alg: Algorithm,
) -> Result<bool, Error> {
    let alg_family = alg.get_family();
    match alg_family {
        AlgorithmFamily::HMAC => verify_hmac(message, signature, key, alg),
        AlgorithmFamily::EC => verify_ec(message, signature, key, alg),
        AlgorithmFamily::RSA => verify_rsa(message, signature, key, alg),
        AlgorithmFamily::OKP => verify_eddsa(message, signature, key, alg),
        _ => return Err(Error::new(crate::errors::UNKNOWN_ALGORITHM)),
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn verify(
    message: String,
    signature: String,
    key: Object,
    alg: Algorithm,
) -> Result<bool, String> {
    let alg_family = alg.get_family();
    match alg_family {
        AlgorithmFamily::HMAC => verify_hmac(
            message,
            signature,
            match HMACKey::from_js_object(key) {
                Ok(val) => val,
                Err(error) => return Err(error.to_string()),
            },
            alg,
        ),
        AlgorithmFamily::EC => verify_ec(message, signature, key, alg),
        AlgorithmFamily::RSA => verify_rsa(
            message,
            signature,
            match RsaVerifyingKey::from_js_object(key) {
                Ok(val) => val,
                Err(error) => return Err(error.to_string()),
            },
            alg,
        ),
        AlgorithmFamily::OKP => verify_eddsa(
            message,
            signature,
            match EDDSAVerifyingKey::from_js_object(key) {
                Ok(val) => val,
                Err(error) => return Err(error.to_string()),
            },
            alg,
        ),
        _ => return Err(Error::new(crate::errors::UNKNOWN_ALGORITHM.to_string())),
    }
}

pub fn get_verifying_key(
    alg: Algorithm,
    key_bytes: &mut [u8],
) -> Result<Box<dyn VerifyFromKey>, Error> {
    match alg {
        Algorithm::ES256 => match P256VerifyingKey::from_bytes(key_bytes) {
            Ok(val) => return Ok(Box::new(val)),
            Err(error) => return Err(error),
        },
        Algorithm::ES256K => match P256kVerifyingKey::from_bytes(key_bytes) {
            Ok(val) => return Ok(Box::new(val)),
            Err(error) => return Err(error),
        },
        Algorithm::ES384 => match P384VerifyingKey::from_bytes(key_bytes) {
            Ok(val) => return Ok(Box::new(val)),
            Err(error) => return Err(error),
        },
        Algorithm::ES512 => match P512VerifyingKey::from_bytes(key_bytes) {
            Ok(val) => return Ok(Box::new(val)),
            Err(error) => return Err(error),
        },
        Algorithm::RS256 => match RsaVerifyingKey::from_bytes(key_bytes) {
            Ok(val) => return Ok(Box::new(val)),
            Err(error) => return Err(error),
        },
        Algorithm::RS384 => match RsaVerifyingKey::from_bytes(key_bytes) {
            Ok(val) => return Ok(Box::new(val)),
            Err(error) => return Err(error),
        },
        Algorithm::RS512 => match RsaVerifyingKey::from_bytes(key_bytes) {
            Ok(val) => return Ok(Box::new(val)),
            Err(error) => return Err(error),
        },
        Algorithm::PS256 => match RsaVerifyingKey::from_bytes(key_bytes) {
            Ok(val) => return Ok(Box::new(val)),
            Err(error) => return Err(error),
        },
        Algorithm::PS384 => match RsaVerifyingKey::from_bytes(key_bytes) {
            Ok(val) => return Ok(Box::new(val)),
            Err(error) => return Err(error),
        },
        Algorithm::PS512 => match RsaVerifyingKey::from_bytes(key_bytes) {
            Ok(val) => return Ok(Box::new(val)),
            Err(error) => return Err(error),
        },
        Algorithm::HS256 => return Err(Error::new(crate::errors::NOT_USING_ASYMMETRIC_KEYS)),
        Algorithm::HS384 => return Err(Error::new(crate::errors::NOT_USING_ASYMMETRIC_KEYS)),
        Algorithm::HS512 => return Err(Error::new(crate::errors::NOT_USING_ASYMMETRIC_KEYS)),
        Algorithm::EdDSA => match EDDSAVerifyingKey::from_bytes(key_bytes) {
            Ok(val) => return Ok(Box::new(val)),
            Err(error) => return Err(error),
        },
    }
}
