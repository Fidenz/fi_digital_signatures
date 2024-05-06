use crate::{algorithms::Algorithm, errors::Error};

use self::{
    _256k::{ec_256k_sign, ec_256k_verify},
    _256::{ec_256_sign, ec_256_verify},
    _384::{ec_384_sign, ec_384_verify},
    _512::{ec_512_sign, ec_512_verify},
};

mod _256;
mod _256k;
mod _384;
mod _512;

pub fn sign_ec(message: String, key: String, alg: Algorithm) -> Result<String, Error> {
    match alg {
        Algorithm::ES256 => ec_256_sign(message, key),
        Algorithm::ES384 => ec_384_sign(message, key),
        Algorithm::ES512 => ec_512_sign(message, key),
        Algorithm::ES256K => ec_256k_sign(message, key),
        _ => return Err(Error::UNKNOWN_ALGORITHM),
    }
}

pub fn verify_ec(
    message: String,
    signature: String,
    key: String,
    alg: Algorithm,
) -> Result<bool, Error> {
    match alg {
        Algorithm::ES256 => ec_256_verify(message, signature, key),
        Algorithm::ES384 => ec_384_verify(message, signature, key),
        Algorithm::ES512 => ec_512_verify(message, signature, key),
        Algorithm::ES256K => ec_256k_verify(message, signature, key),
        _ => return Err(Error::UNKNOWN_ALGORITHM),
    }
}
