use crate::crypto::rsa::verify_rsa;
use crate::{
    algorithms::{Algorithm, AlgorithmFamily},
    errors::Error,
};

pub fn verify(
    message: String,
    signature: String,
    key: String,
    alg: Algorithm,
) -> Result<bool, Error> {
    let alg_family = alg.get_family();
    match alg_family {
        AlgorithmFamily::RSA => verify_rsa(message, signature, key, alg),
        _ => return Err(Error::UNKNOWN_ALGORITHM),
    }
}
