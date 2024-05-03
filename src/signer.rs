use crate::algorithms::{Algorithm, AlgorithmFamily};
use crate::errors::Error;
use crate::log;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::Signature;
use rsa::pkcs8::DecodePrivateKey;
use rsa::sha2::{Sha256, Sha384, Sha512};
use rsa::signature::{RandomizedSigner, SignatureEncoding, SignerMut};

pub fn sign(message: String, key: String, alg: Algorithm) -> Result<String, Error> {
    let alg_family = alg.get_family();
    match alg_family {
        AlgorithmFamily::RSA => sign_rsa(message, key, alg),
        _ => return Err(Error::UNKNOWN_ALGORITHM),
    }
}

fn sign_rsa(message: String, key_str: String, alg: Algorithm) -> Result<String, Error> {
    let rsa_key = match key_str.starts_with("-----BEGIN RSA PRIVATE KEY-----") {
        true => match rsa::RsaPrivateKey::from_pkcs1_pem(key_str.as_str()) {
            Ok(val) => val,
            Err(error) => {
                log::error(error.to_string().as_str());
                return Err(Error::PRIVATE_KEY_IDENTIFICATION_ERROR);
            }
        },
        false => match rsa::RsaPrivateKey::from_pkcs8_pem(key_str.as_str()) {
            Ok(val) => val,
            Err(error) => {
                log::error(error.to_string().as_str());
                return Err(Error::PRIVATE_KEY_IDENTIFICATION_ERROR);
            }
        },
    };

    let mut rng = rand::thread_rng();
    if alg.to_str().starts_with("RS") {
        let sig: Signature = match alg {
            Algorithm::RS256 => {
                let mut signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(rsa_key);
                signing_key.sign(message.as_bytes())
            }
            Algorithm::RS384 => {
                let mut signing_key = rsa::pkcs1v15::SigningKey::<Sha384>::new(rsa_key);
                signing_key.sign(message.as_bytes())
            }
            Algorithm::RS512 => {
                let mut signing_key = rsa::pkcs1v15::SigningKey::<Sha512>::new(rsa_key);
                signing_key.sign(message.as_bytes())
            }
            _ => return Err(Error::UNKNOWN_ALGORITHM),
        };
        let bytes = sig.to_bytes();
        Ok(base64_url::encode(&bytes))
    } else {
        let sig = match alg {
            Algorithm::PS256 => {
                let signing_key = rsa::pss::SigningKey::<Sha256>::new(rsa_key);
                signing_key.sign_with_rng(&mut rng, message.as_bytes())
            }
            Algorithm::PS384 => {
                let signing_key = rsa::pss::SigningKey::<Sha384>::new(rsa_key);
                signing_key.sign_with_rng(&mut rng, message.as_bytes())
            }
            Algorithm::PS512 => {
                let signing_key = rsa::pss::SigningKey::<Sha512>::new(rsa_key);
                signing_key.sign_with_rng(&mut rng, message.as_bytes())
            }
            _ => return Err(Error::UNKNOWN_ALGORITHM),
        };

        let bytes = sig.to_bytes();
        Ok(base64_url::encode(&bytes))
    }
}
