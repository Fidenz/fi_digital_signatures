use serde::{Deserialize, Serialize};

#[derive(PartialEq, Eq, Serialize, Deserialize, Copy, Clone)]
pub enum Algorithm {
    RS256,
    RS384,
    RS512,
    PS256,
    PS384,
    PS512,
    ES256,
    ES384,
    ES512,
    ES256K,
    EdDSA,
}

impl Algorithm {
    pub fn to_str<'a>(&self) -> &'a str {
        match self {
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

pub enum AlgorithmFamily {
    EC,
    RSA,
    OKP,
    None,
}
