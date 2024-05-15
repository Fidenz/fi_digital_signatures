use crate::{
    algorithms::{Algorithm, AlgorithmFamily},
    crypto::{
        ecdsa::verify_ec, eddsa::verify_eddsa, hmac::verify_hmac, rsa::verify_rsa, VerifyFromKey,
    },
    errors::Error,
};

/// Verify the signature with a provided Key
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
