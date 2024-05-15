use crate::{
    algorithms::{Algorithm, AlgorithmFamily},
    crypto::{ecdsa::sign_ec, eddsa::sign_eddsa, hmac::sign_hmac, rsa::sign_rsa, SignFromKey},
    errors::Error,
};

/// Signs the content with a provided Key
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
