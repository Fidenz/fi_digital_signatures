use crate::errors::Error;
use crate::{algorithms::Algorithm, log};
use generic_array::typenum::{IsLess, Le, NonZero, U256};
use hmac::Hmac;
use hmac::Mac;
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

use super::SignFromKey;
use super::VerifyFromKey;

pub struct HMACKey {
    key: String,
}

impl HMACKey {
    pub fn new(pass: String) -> Self {
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
}

impl SignFromKey for HMACKey {
    fn sign(
        &self,
        content: String,
        alg: crate::algorithms::Algorithm,
    ) -> Result<String, crate::errors::Error> {
        match alg {
            Algorithm::HS256 => self.hmac_sign::<Sha256>(content),
            Algorithm::HS384 => self.hmac_sign::<Sha384>(content),
            Algorithm::HS512 => self.hmac_sign::<Sha512>(content),
            _ => panic!(),
        }
    }
}

impl VerifyFromKey for HMACKey {
    fn verify(
        &self,
        content: String,
        signature: String,
        alg: Algorithm,
    ) -> Result<bool, crate::errors::Error> {
        match alg {
            Algorithm::HS256 => self.hmac_verify::<Sha256>(content, signature),
            Algorithm::HS384 => self.hmac_verify::<Sha384>(content, signature),
            Algorithm::HS512 => self.hmac_verify::<Sha512>(content, signature),
            _ => panic!(),
        }
    }
}
