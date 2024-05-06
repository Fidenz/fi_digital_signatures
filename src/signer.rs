use crate::{
    algorithms::{Algorithm, AlgorithmFamily},
    crypto::{ecdsa::sign_ec, rsa::sign_rsa},
    errors::Error,
};

pub fn sign(message: String, key: String, alg: Algorithm) -> Result<String, Error> {
    let alg_family = alg.get_family();
    match alg_family {
        AlgorithmFamily::EC => sign_ec(message, key, alg),
        AlgorithmFamily::RSA => sign_rsa(message, key, alg),
        _ => return Err(Error::UNKNOWN_ALGORITHM),
    }
}
