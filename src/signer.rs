use crate::{
    algorithms::{Algorithm, AlgorithmFamily},
    crypto::{ecdsa::sign_ec, eddsa::sign_eddsa, hmac::sign_hmac, rsa::sign_rsa},
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
pub fn sign(message: String, key: Object, alg: Algorithm) -> Result<String, Error> {
    let alg_family = alg.get_family();
    match alg_family {
        AlgorithmFamily::HMAC => sign_hmac(
            message,
            match HMACKey::from_js_object(key) {
                Ok(val) => val,
                Err(error) => return Err(error),
            },
            alg,
        ),
        AlgorithmFamily::RSA => sign_rsa(
            message,
            match RsaSigningKey::from_js_object(key) {
                Ok(val) => val,
                Err(error) => return Err(error),
            },
            alg,
        ),
        AlgorithmFamily::EC => sign_ec(message, key, alg),
        AlgorithmFamily::OKP => sign_eddsa(
            message,
            match EDDSASigningKey::from_js_object(key) {
                Ok(val) => val,
                Err(error) => return Err(error),
            },
            alg,
        ),
        _ => return Err(Error::UNKNOWN_ALGORITHM),
    }
}
