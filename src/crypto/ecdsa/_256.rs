use crate::{errors::Error, log};
use p256::{
    ecdsa::{
        signature::{Signer, Verifier},
        Signature, SigningKey, VerifyingKey,
    },
    NistP256,
};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};

pub fn ec_256_sign(message: String, key: String) -> Result<String, Error> {
    let ec_key = match key.starts_with("-----BEGIN EC PRIVATE KEY-----") {
        true => {
            let key_scalar: elliptic_curve::SecretKey<NistP256> =
                match elliptic_curve::SecretKey::from_sec1_pem(key.as_str()) {
                    Ok(val) => val,
                    Err(error) => {
                        log::error(error.to_string().as_str());
                        return Err(Error::EC_PEM_ERROR);
                    }
                };

            match SigningKey::from_bytes(&key_scalar.as_scalar_primitive().to_bytes()) {
                Ok(val) => val,
                Err(error) => {
                    log::error(error.to_string().as_str());
                    return Err(Error::PRIVATE_KEY_IDENTIFICATION_ERROR);
                }
            }
        }
        false => match SigningKey::from_pkcs8_pem(key.as_str()) {
            Ok(val) => val,
            Err(error) => {
                log::error(error.to_string().as_str());
                return Err(Error::PRIVATE_KEY_IDENTIFICATION_ERROR);
            }
        },
    };

    let sig_result: Result<Signature, p256::ecdsa::Error> = ec_key.try_sign(message.as_bytes());
    let signature = match sig_result {
        Ok(val) => val,
        Err(error) => {
            log::error(error.to_string().as_str());
            return Err(Error::SIGNING_FAILED);
        }
    };

    Ok(base64_url::encode(signature.to_bytes().as_slice()))
}

pub fn ec_256_verify(message: String, sig: String, key: String) -> Result<bool, Error> {
    let key_scalar: elliptic_curve::PublicKey<NistP256> =
        match elliptic_curve::PublicKey::from_public_key_pem(key.as_str()) {
            Ok(val) => val,
            Err(error) => {
                log::error(error.to_string().as_str());
                return Err(Error::EC_PEM_ERROR);
            }
        };
    let ec_key = match VerifyingKey::from_sec1_bytes(&key_scalar.to_sec1_bytes()) {
        Ok(val) => val,
        Err(error) => {
            log::error(error.to_string().as_str());
            return Err(Error::PUBLIC_KEY_IDENTIFICATION_ERROR);
        }
    };

    let decoded_sig = match base64_url::decode(sig.as_bytes()) {
        Ok(val) => val,
        Err(error) => {
            log::error(error.to_string().as_str());
            return Err(Error::DECODING_ERROR);
        }
    };

    let signature = match Signature::from_slice(&decoded_sig) {
        Ok(val) => val,
        Err(error) => {
            log::error(error.to_string().as_str());
            return Err(Error::SIGNATURE_IDENTIFICATION_FAILED);
        }
    };

    let verify_result: Result<(), p256::ecdsa::Error> =
        ec_key.verify(message.as_bytes(), &signature);
    if verify_result.is_ok() {
        return Ok(true);
    } else {
        match verify_result.err() {
            Some(error) => {
                log::error(error.to_string().as_str());
            }
            None => {}
        };
        return Ok(false);
    }
}
