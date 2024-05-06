use crate::crypto::{ecdsa::verify_ec, eddsa::verify_eddsa, rsa::verify_rsa};
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
        AlgorithmFamily::EC => verify_ec(message, signature, key, alg),
        AlgorithmFamily::OKP => verify_eddsa(message, signature, key),
        _ => return Err(Error::UNKNOWN_ALGORITHM),
    }
}
