use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::wasm_bindgen;

/// Algorithms that used to sign and verify content
#[derive(PartialEq, Eq, Serialize, Deserialize, Copy, Clone)]
#[wasm_bindgen]
pub enum Algorithm {
    /// Sha-256 hash function based HMAC hash algotithm
    HS256,
    /// Sha-384 hash function based HMAC hash algotithm
    HS384,
    /// Sha-256 hash function based HMAC hash algotithm
    HS512,
    /// Sha-256 based RSA algorithm
    RS256,
    /// Sha-384 based RSA algorithm
    RS384,
    /// Sha-512 based RSA algorithm
    RS512,
    /// RSASSA-PSS using SHA-256
    PS256,
    /// RSASSA-PSS using SHA-384
    PS384,
    /// RSASSA-PSS using SHA-512
    PS512,
    /// Elliptic curve with NistP256
    ES256,
    /// Elliptic curve with NistP384
    ES384,
    /// Elliptic curve with NistP512
    ES512,
    /// Elliptic curve with Secp256k1
    ES256K,
    /// Elliptic curve with Ed25519
    EdDSA,
}

impl Algorithm {
    pub fn to_str<'a>(&self) -> &'a str {
        match self {
            Algorithm::HS256 => "HS256",
            Algorithm::HS384 => "HS384",
            Algorithm::HS512 => "HS512",
            Algorithm::RS256 => "RS256",
            Algorithm::RS384 => "RS384",
            Algorithm::RS512 => "RS512",
            Algorithm::PS256 => "PS256",
            Algorithm::PS384 => "PS384",
            Algorithm::PS512 => "PS512",
            Algorithm::ES256 => "ES256",
            Algorithm::ES384 => "ES384",
            Algorithm::ES512 => "ES512",
            Algorithm::ES256K => "ES256K",
            Algorithm::EdDSA => "EdDSA",
        }
    }

    pub fn from_str(alg: &str) -> Option<Self> {
        match alg {
            "HS256" => Some(Algorithm::HS256),
            "HS384" => Some(Algorithm::HS384),
            "HS512" => Some(Algorithm::HS512),
            "RS256" => Some(Algorithm::RS256),
            "RS384" => Some(Algorithm::RS384),
            "RS512" => Some(Algorithm::RS512),
            "PS256" => Some(Algorithm::PS256),
            "PS384" => Some(Algorithm::PS384),
            "PS512" => Some(Algorithm::PS512),
            "ES256" => Some(Algorithm::ES256),
            "ES384" => Some(Algorithm::ES384),
            "ES512" => Some(Algorithm::ES512),
            "ES256K" => Some(Algorithm::ES256K),
            "EdDSA" => Some(Algorithm::EdDSA),
            _ => None,
        }
    }

    pub fn get_family(&self) -> AlgorithmFamily {
        match self {
            Algorithm::HS256 => AlgorithmFamily::HMAC,
            Algorithm::HS384 => AlgorithmFamily::HMAC,
            Algorithm::HS512 => AlgorithmFamily::HMAC,
            Algorithm::RS256 => AlgorithmFamily::RSA,
            Algorithm::RS384 => AlgorithmFamily::RSA,
            Algorithm::RS512 => AlgorithmFamily::RSA,
            Algorithm::PS256 => AlgorithmFamily::RSA,
            Algorithm::PS384 => AlgorithmFamily::RSA,
            Algorithm::PS512 => AlgorithmFamily::RSA,
            Algorithm::ES256 => AlgorithmFamily::EC,
            Algorithm::ES384 => AlgorithmFamily::EC,
            Algorithm::ES512 => AlgorithmFamily::EC,
            Algorithm::ES256K => AlgorithmFamily::EC,
            Algorithm::EdDSA => AlgorithmFamily::OKP,
        }
    }
}

/// Algorithm family of [`Algorithm`]
#[wasm_bindgen]
pub enum AlgorithmFamily {
    /// [`crate::algorithms::Algorithm::HS256`]
    /// [`crate::algorithms::Algorithm::HS384`]
    /// [`crate::algorithms::Algorithm::HS512`]
    HMAC,
    /// [`crate::algorithms::Algorithm::ES256`]
    /// [`crate::algorithms::Algorithm::ES384`]
    /// [`crate::algorithms::Algorithm::ES512`]
    /// [`crate::algorithms::Algorithm::ES256K`]
    EC,
    /// [`crate::algorithms::Algorithm::RS256`]
    /// [`crate::algorithms::Algorithm::RS384`]
    /// [`crate::algorithms::Algorithm::RS512`]
    /// [`crate::algorithms::Algorithm::PS256`]
    /// [`crate::algorithms::Algorithm::PS384`]
    /// [`crate::algorithms::Algorithm::PS512`]
    RSA,
    /// [`crate::algorithms::Algorithm::EdDSA`]
    OKP,
    None,
}

impl AlgorithmFamily {
    pub fn to_str(&self) -> &str {
        match self {
            AlgorithmFamily::HMAC => "HMAC",
            AlgorithmFamily::EC => "EC",
            AlgorithmFamily::RSA => "RSA",
            AlgorithmFamily::OKP => "OKP",
            _ => "None",
        }
    }

    pub fn to_string(&self) -> String {
        String::from(self.to_str())
    }
}
