use serde::{Deserialize, Serialize};

#[derive(PartialEq, Eq, Serialize, Deserialize, Copy, Clone)]
pub enum Algorithm {
    HS256,
    HS384,
    HS512,
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
    // ES256KR,
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
            // Algorithm::ES256KR => "ES256K-R",
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
            // "ES256K-R" => Some(Algorithm::ES256KR),
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
            // Algorithm::ES256KR => AlgorithmFamily::Special,
            Algorithm::EdDSA => AlgorithmFamily::OKP,
        }
    }
}

pub enum AlgorithmFamily {
    HMAC,
    EC,
    RSA,
    OKP,
    Special,
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
