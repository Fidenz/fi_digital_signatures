use crate::{algorithms::Algorithm, errors::Error, log};
use generic_array::typenum::{IsLess, Le, NonZero, U256};
use hmac::Hmac;
use hmac::Mac;
use js_sys::Object;
use sha2::Sha384;
use sha2::Sha512;
use sha2::{
    digest::{
        block_buffer::Eager,
        core_api::{BlockSizeUser, BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore},
        HashMarker,
    },
    Sha256,
};
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

use super::SignFromKey;
use super::VerifyFromKey;

/// Signing key for HMAC algorithm
#[derive(Clone)]
#[wasm_bindgen]
pub struct HMACKey {
    key: String,
}

#[wasm_bindgen]
impl HMACKey {
    /// Create new <b>HMACKey</b> instance
    #[wasm_bindgen(constructor)]
    pub fn new(pass: String) -> HMACKey {
        HMACKey { key: pass }
    }

    fn hmac_sign<T>(&self, content: String) -> Result<String, Error>
    where
        T: CoreProxy,
        T::Core: HashMarker
            + UpdateCore
            + FixedOutputCore
            + BufferKindUser<BufferKind = Eager>
            + Default
            + Clone,
        <T::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<T::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    {
        let mut hmac_wrapper = match Hmac::<T>::new_from_slice(self.key.as_bytes()) {
            Ok(val) => val,
            Err(error) => {
                log::error(error.to_string().as_str());
                return Err(Error::HMAC_KEY_ERROR);
            }
        };

        hmac_wrapper.update(content.as_bytes());

        let signed_bytes = hmac_wrapper.finalize().into_bytes();
        Ok(base64_url::encode(&signed_bytes.to_vec()))
    }

    fn hmac_verify<T>(&self, content: String, signature: String) -> Result<bool, Error>
    where
        T: CoreProxy,
        T::Core: HashMarker
            + UpdateCore
            + FixedOutputCore
            + BufferKindUser<BufferKind = Eager>
            + Default
            + Clone,
        <T::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<T::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    {
        let sig = match base64_url::decode(&signature) {
            Ok(val) => val,
            Err(error) => {
                log::error(error.to_string().as_str());
                return Err(Error::DECODING_ERROR);
            }
        };

        let mut hmac_wrapper = match Hmac::<T>::new_from_slice(self.key.as_bytes()) {
            Ok(val) => val,
            Err(error) => {
                log::error(error.to_string().as_str());
                return Err(Error::HMAC_KEY_ERROR);
            }
        };

        hmac_wrapper.update(content.as_bytes());

        match hmac_wrapper.verify_slice(sig.as_slice()) {
            Ok(()) => Ok(true),
            Err(error) => {
                log::error(error.to_string().as_str());
                return Ok(false);
            }
        }
    }

    pub fn from_js_object(value: Object) -> Result<HMACKey, Error> {
        let phrase = JsValue::from_str("passphrase");

        if value.has_own_property(&phrase) {
            let phrase = match js_sys::Reflect::get(&value, &phrase) {
                Ok(val) => val.as_string().unwrap(),
                Err(error) => {
                    log::error(error.as_string().unwrap().as_str());
                    return Err(Error::MISSING_FIELD);
                }
            };

            return Ok(HMACKey::new(phrase));
        }

        Err(Error::MISSING_FIELD)
    }
}

impl SignFromKey for HMACKey {
    fn sign(&self, content: String, alg: crate::algorithms::Algorithm) -> Result<String, Error> {
        match alg {
            Algorithm::HS256 => self.hmac_sign::<Sha256>(content),
            Algorithm::HS384 => self.hmac_sign::<Sha384>(content),
            Algorithm::HS512 => self.hmac_sign::<Sha512>(content),
            _ => Err(Error::UNKNOWN_ALGORITHM),
        }
    }
}

impl VerifyFromKey for HMACKey {
    fn verify(&self, content: String, signature: String, alg: Algorithm) -> Result<bool, Error> {
        match alg {
            Algorithm::HS256 => self.hmac_verify::<Sha256>(content, signature),
            Algorithm::HS384 => self.hmac_verify::<Sha384>(content, signature),
            Algorithm::HS512 => self.hmac_verify::<Sha512>(content, signature),
            _ => Err(Error::UNKNOWN_ALGORITHM),
        }
    }
}

/// Sign the content with the HMAC pass phrase
pub fn sign_hmac(message: String, key: impl SignFromKey, alg: Algorithm) -> Result<String, Error> {
    key.sign(message, alg)
}

/// Verify the signature with the HMAC pass phrase
pub fn verify_hmac(
    message: String,
    signature: String,
    key: impl VerifyFromKey,
    alg: Algorithm,
) -> Result<bool, Error> {
    key.verify(message, signature, alg)
}
