#[cfg(not(feature = "wasm"))]
use crate::crypto::VerifyFromKey;
#[cfg(feature = "wasm")]
use crate::crypto::{eddsa::EDDSAVerifyingKey, hmac::HMACKey, rsa::RsaVerifyingKey};
use crate::{
    algorithms::{Algorithm, AlgorithmFamily},
    crypto::{ecdsa::verify_ec, eddsa::verify_eddsa, hmac::verify_hmac, rsa::verify_rsa},
    errors::Error,
};
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
        _ => return Err(Error::UNKNOWN_ALGORITHM),
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
        _ => return Err(Error::UNKNOWN_ALGORITHM.to_string()),
    }
}
