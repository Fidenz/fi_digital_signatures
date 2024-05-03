use rsa::{
    pkcs1::DecodeRsaPublicKey,
    pkcs8::DecodePublicKey,
    sha2::{Sha256, Sha384, Sha512},
    signature::Verifier,
};

use crate::log;
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
        // AlgorithmFamily::EC => sign_ec(message, key, alg),
        AlgorithmFamily::RSA => verify_rsa(message, signature, key, alg),
        _ => return Err(Error::UNKNOWN_ALGORITHM),
    }
}

fn verify_rsa(
    message: String,
    signature: String,
    key_str: String,
    alg: Algorithm,
) -> Result<bool, Error> {
    let rsa_key = match key_str.starts_with("-----BEGIN RSA PUBLIC KEY-----") {
        true => match rsa::RsaPublicKey::from_pkcs1_pem(key_str.as_str()) {
            Ok(val) => val,
            Err(error) => {
                log::error(error.to_string().as_str());
                return Err(Error::PRIVATE_KEY_IDENTIFICATION_ERROR);
            }
        },
        false => match rsa::RsaPublicKey::from_public_key_pem(key_str.as_str()) {
            Ok(val) => val,
            Err(error) => {
                log::error(error.to_string().as_str());
                return Err(Error::PRIVATE_KEY_IDENTIFICATION_ERROR);
            }
        },
    };

    let decoded_sig_data = match base64_url::decode(&signature) {
        Ok(val) => val,
        Err(error) => {
            log::error(error.to_string().as_str());
            return Err(Error::DECODING_ERROR);
        }
    };

    if alg.to_str().starts_with("RS") {
        let sig = match rsa::pkcs1v15::Signature::try_from(decoded_sig_data.as_slice()) {
            Ok(val) => val,
            Err(error) => {
                log::error(error.to_string().as_str());
                return Err(Error::SIGNATURE_IDENTIFICATION_FAILED);
            }
        };

        let verification = match alg {
            Algorithm::RS256 => {
                let verifying_key = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(rsa_key);
                verifying_key.verify(message.as_bytes(), &sig)
            }
            Algorithm::RS384 => {
                let verifying_key = rsa::pkcs1v15::VerifyingKey::<Sha384>::new(rsa_key);
                verifying_key.verify(message.as_bytes(), &sig)
            }
            Algorithm::RS512 => {
                let verifying_key = rsa::pkcs1v15::VerifyingKey::<Sha512>::new(rsa_key);
                verifying_key.verify(message.as_bytes(), &sig)
            }
            _ => return Err(Error::UNKNOWN_ALGORITHM),
        };

        if verification.is_ok() {
            return Ok(true);
        } else {
            match verification.err() {
                Some(val) => {
                    log::error(val.to_string().as_str());
                }
                None => {}
            }
            return Ok(false);
        }
    } else {
        let sig = match rsa::pss::Signature::try_from(decoded_sig_data.as_slice()) {
            Ok(val) => val,
            Err(error) => {
                log::error(error.to_string().as_str());
                return Err(Error::SIGNATURE_IDENTIFICATION_FAILED);
            }
        };

        let verification = match alg {
            Algorithm::RS256 => {
                let verifying_key = rsa::pss::VerifyingKey::<Sha256>::new(rsa_key);
                verifying_key.verify(message.as_bytes(), &sig)
            }
            Algorithm::RS384 => {
                let verifying_key = rsa::pss::VerifyingKey::<Sha384>::new(rsa_key);
                verifying_key.verify(message.as_bytes(), &sig)
            }
            Algorithm::RS512 => {
                let verifying_key = rsa::pss::VerifyingKey::<Sha512>::new(rsa_key);
                verifying_key.verify(message.as_bytes(), &sig)
            }
            _ => return Err(Error::UNKNOWN_ALGORITHM),
        };

        if verification.is_ok() {
            return Ok(true);
        } else {
            match verification.err() {
                Some(val) => {
                    log::error(val.to_string().as_str());
                }
                None => {}
            }
            return Ok(false);
        }
    }
}
