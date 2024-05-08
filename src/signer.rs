use crate::{
    algorithms::{Algorithm, AlgorithmFamily},
    crypto::{ecdsa::sign_ec, eddsa::sign_eddsa, rsa::sign_rsa, SignFromKey},
    errors::Error,
};

pub fn sign(message: String, key: impl SignFromKey, alg: Algorithm) -> Result<String, Error> {
    let alg_family = alg.get_family();
    match alg_family {
        AlgorithmFamily::RSA => sign_rsa(message, key, alg),
        AlgorithmFamily::EC => sign_ec(message, key, alg),
        AlgorithmFamily::OKP => sign_eddsa(message, key, alg),
        _ => return Err(Error::UNKNOWN_ALGORITHM),
    }
}
