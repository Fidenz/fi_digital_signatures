pub enum Algorithm {
    RS256,
    RS318,
    RS512,
    PS256,
    PS318,
    PS512,
    ES256,
    ES318,
    ES512,
    ES512K,
    ES512KR,
    EdDSA,
}

impl Algorithm {
    pub fn to_str<'a>(&self) -> &'a str {
        match self {
            Algorithm::RS256 => "RS256",
            Algorithm::RS318 => "RS318",
            Algorithm::RS512 => "RS512",
            Algorithm::PS256 => "PS256",
            Algorithm::PS318 => "PS318",
            Algorithm::PS512 => "PS512",
            Algorithm::ES256 => "ES256",
            Algorithm::ES318 => "ES318",
            Algorithm::ES512 => "ES512",
            Algorithm::ES512K => "ES512K",
            Algorithm::ES512KR => "ES512K-R",
            Algorithm::EdDSA => "EdDSA",
        }
    }

    pub fn from_str(alg: &str) -> Option<Self> {
        match alg {
            "RS256" => Some(Algorithm::RS256),
            "RS318" => Some(Algorithm::RS318),
            "RS512" => Some(Algorithm::RS512),
            "PS256" => Some(Algorithm::PS256),
            "PS318" => Some(Algorithm::PS318),
            "PS512" => Some(Algorithm::PS512),
            "ES256" => Some(Algorithm::ES256),
            "ES318" => Some(Algorithm::ES318),
            "ES512" => Some(Algorithm::ES512),
            "ES512K" => Some(Algorithm::ES512K),
            "ES512K-R" => Some(Algorithm::ES512KR),
            "EdDSA" => Some(Algorithm::EdDSA),
            _ => None,
        }
    }

    pub fn get_family(&self) -> AlgorithmFamily {
        match self {
            Algorithm::RS256 => AlgorithmFamily::RSA,
            Algorithm::RS318 => AlgorithmFamily::RSA,
            Algorithm::RS512 => AlgorithmFamily::RSA,
            Algorithm::PS256 => AlgorithmFamily::RSA,
            Algorithm::PS318 => AlgorithmFamily::RSA,
            Algorithm::PS512 => AlgorithmFamily::RSA,
            Algorithm::ES256 => AlgorithmFamily::EC,
            Algorithm::ES318 => AlgorithmFamily::EC,
            Algorithm::ES512 => AlgorithmFamily::EC,
            Algorithm::ES512K => AlgorithmFamily::EC,
            Algorithm::ES512KR => AlgorithmFamily::Special,
            Algorithm::EdDSA => AlgorithmFamily::OKP,
        }
    }
}

pub enum AlgorithmFamily {
    EC,
    RSA,
    OKP,
    Special,
    None,
}
