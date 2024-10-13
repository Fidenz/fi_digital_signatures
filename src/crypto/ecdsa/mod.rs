#[cfg(feature = "wasm")]
use self::{
    _256k::P256kSigningKey,
    _256::{P256SigningKey, P256VerifyingKey},
    _384::{P384SigningKey, P384VerifyingKey},
    _512::{P512SigningKey, P512VerifyingKey},
};
use self::{
    _256k::{ec_256k_sign, ec_256k_verify},
    _256::{ec_256_sign, ec_256_verify},
    _384::{ec_384_sign, ec_384_verify},
    _512::{ec_512_sign, ec_512_verify},
};
use crate::algorithms::Algorithm;
#[cfg(not(feature = "wasm"))]
use crate::crypto::{SignFromKey, VerifyFromKey};
use fi_common::error::Error;
#[cfg(feature = "wasm")]
use js_sys::Object;

/// EC signing & verifying with NistP256 curve
pub mod _256;
/// EC signing & verifying with Secp256k1 curve
pub mod _256k;
/// EC signing & verifying with NistP384 curve
pub mod _384;
/// EC signing & verifying with NistP521 curve
pub mod _512;

/// Sign content with EC based algorithms
#[cfg(not(feature = "wasm"))]
pub fn sign_ec(message: String, key: impl SignFromKey, alg: Algorithm) -> Result<String, Error> {
    match alg {
        Algorithm::ES256 => ec_256_sign(message, key),
        Algorithm::ES384 => ec_384_sign(message, key),
        Algorithm::ES512 => ec_512_sign(message, key),
        Algorithm::ES256K => ec_256k_sign(message, key),
        _ => return Err(Error::new(crate::errors::UNKNOWN_ALGORITHM)),
    }
}

#[cfg(feature = "wasm")]
pub fn sign_ec(message: String, key: Object, alg: Algorithm) -> Result<String, String> {
    match alg {
        Algorithm::ES256 => ec_256_sign(
            message,
            match P256SigningKey::from_js_object(key) {
                Ok(val) => val,
                Err(error) => return Err(error.to_string()),
            },
        ),
        Algorithm::ES384 => ec_384_sign(
            message,
            match P384SigningKey::from_js_object(key) {
                Ok(val) => val,
                Err(error) => return Err(error.to_string()),
            },
        ),
        Algorithm::ES512 => ec_512_sign(
            message,
            match P512SigningKey::from_js_object(key) {
                Ok(val) => val,
                Err(error) => return Err(error.to_string()),
            },
        ),
        Algorithm::ES256K => ec_256k_sign(
            message,
            match P256kSigningKey::from_js_object(key) {
                Ok(val) => val,
                Err(error) => return Err(error.to_string()),
            },
        ),
        _ => return Err(Error::new(crate::errors::UNKNOWN_ALGORITHM.to_string())),
    }
}

/// Verify signature with EC based algorithms
#[cfg(not(feature = "wasm"))]
pub fn verify_ec(
    message: String,
    signature: String,
    key: impl VerifyFromKey,
    alg: Algorithm,
) -> Result<bool, Error> {
    match alg {
        Algorithm::ES256 => ec_256_verify(message, signature, key),
        Algorithm::ES384 => ec_384_verify(message, signature, key),
        Algorithm::ES512 => ec_512_verify(message, signature, key),
        Algorithm::ES256K => ec_256k_verify(message, signature, key),
        _ => return Err(Error::new(crate::errors::UNKNOWN_ALGORITHM)),
    }
}

#[cfg(feature = "wasm")]
pub fn verify_ec(
    message: String,
    signature: String,
    key: Object,
    alg: Algorithm,
) -> Result<bool, String> {
    match alg {
        Algorithm::ES256 => ec_256_verify(
            message,
            signature,
            match P256VerifyingKey::from_js_object(key) {
                Ok(val) => val,
                Err(error) => return Err(error.to_string()),
            },
        ),
        Algorithm::ES384 => ec_384_verify(
            message,
            signature,
            match P384VerifyingKey::from_js_object(key) {
                Ok(val) => val,
                Err(error) => return Err(error.to_string()),
            },
        ),
        Algorithm::ES512 => ec_512_verify(
            message,
            signature,
            match P512VerifyingKey::from_js_object(key) {
                Ok(val) => val,
                Err(error) => return Err(error.to_string()),
            },
        ),
        Algorithm::ES256K => ec_256k_verify(
            message,
            signature,
            match P256VerifyingKey::from_js_object(key) {
                Ok(val) => val,
                Err(error) => return Err(error.to_string()),
            },
        ),
        _ => return Err(Error::new(crate::errors::UNKNOWN_ALGORITHM.to_string())),
    }
}
