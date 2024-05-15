use crate::{
    algorithms::Algorithm,
    crypto::{SignFromKey, VerifyFromKey},
    errors::Error,
    log,
    signer::sign,
    verifier::verify,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Utc};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;

trait Base64Encode
where
    Self: Serialize + ToString,
{
    fn to_base64_encoded(&self) -> String {
        STANDARD.encode(self.to_string())
    }
}

trait FromBase64Encoded
where
    Self: DeserializeOwned,
{
    fn from_base64_encoded(base64_encoded_str: &str) -> Result<Self, Error> {
        let base64_decoded = match STANDARD.decode(base64_encoded_str) {
            Ok(val) => match String::from_utf8(val) {
                Ok(val) => val,
                Err(error) => {
                    log::error(error.to_string().as_str());
                    return Err(Error::JWT_UTF8_ERROR);
                }
            },
            Err(error) => {
                log::error(error.to_string().as_str());
                return Err(Error::DECODING_ERROR);
            }
        };

        match serde_json::from_str(base64_decoded.as_str()) {
            Ok(val) => Ok(val),
            Err(error) => {
                log::error(error.to_string().as_str());
                return Err(Error::JWT_HEADER_DESERIALIZING_ERROR);
            }
        }
    }
}

/// JWT token header
#[derive(Serialize, Deserialize)]
pub struct Header {
    pub typ: String,
    pub alg: Algorithm,
    pub kid: String,
}

impl Header {
    /// Create JWT header instance
    pub fn new(kid: String, alg: Algorithm) -> Self {
        Header {
            kid,
            alg,
            typ: String::from("JWT"),
        }
    }
}

impl ToString for Header {
    fn to_string(&self) -> String {
        match serde_json::to_string(self) {
            Ok(val) => val,
            Err(error) => {
                log::error(error.to_string().as_str());
                panic!()
            }
        }
    }
}

impl FromBase64Encoded for Header {}
impl Base64Encode for Header {}

/// JWT token payload. [`serde_json::Value`]
#[derive(Serialize, Deserialize)]
pub struct Payload(pub Value);

impl ToString for Payload {
    fn to_string(&self) -> String {
        match serde_json::to_string(self) {
            Ok(val) => val,
            Err(error) => {
                log::error(error.to_string().as_str());
                panic!()
            }
        }
    }
}

impl FromBase64Encoded for Payload {}
impl Base64Encode for Payload {}

/// JWT token signature
#[derive(Serialize, Deserialize, Clone)]
pub struct Signature(String);

impl ToString for Signature {
    fn to_string(&self) -> String {
        self.0.clone()
    }
}

/// JWT token object
#[derive(Serialize, Deserialize)]
pub struct JWT {
    pub header: Header,
    pub payload: Payload,
    pub signature: Option<Signature>,
}

impl JWT {
    /// Retrive jwt token from [`JWT`] token object
    pub fn to_token(&self) -> Result<String, Error> {
        if self.signature.is_none() {
            return Err(Error::JWT_TOKEN_NOT_SIGNED);
        } else {
            let sig = self.signature.as_ref().unwrap();
            Ok(format!(
                "{}.{}.{}",
                self.header.to_base64_encoded(),
                self.payload.to_base64_encoded(),
                sig.to_string()
            ))
        }
    }

    /// Sign the current [`JWT`] token object
    pub fn sign(&mut self, private_key: impl SignFromKey) -> Result<(), Error> {
        let content = format!(
            "{}.{}",
            self.header.to_base64_encoded(),
            self.payload.to_base64_encoded()
        );

        match sign(content.clone(), private_key, self.header.alg) {
            Ok(val) => {
                self.signature = Some(Signature(val));
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    /// Create [`JWT`] token instance from JWT token string
    pub fn from_token(token: &str) -> Result<Self, Error> {
        let token_content: Vec<&str> = token.split(".").collect();

        let header = match Header::from_base64_encoded(token_content[0]) {
            Ok(val) => val,
            Err(error) => return Err(error),
        };

        let payload = match Payload::from_base64_encoded(token_content[1]) {
            Ok(val) => val,
            Err(error) => return Err(error),
        };

        let signature: Signature = Signature(String::from(token_content[2]));

        Ok(JWT {
            header,
            payload,
            signature: Some(signature),
        })
    }

    fn check_if_expired(timestamp_secs: i64) -> Result<bool, Error> {
        let now = Utc::now();
        let exp_time = match DateTime::from_timestamp_millis(timestamp_secs * 1000) {
            Some(val) => val,
            None => {
                return Err(Error::FAILED_TO_CONVERT_TIMESTAMP_TO_DATETTIME);
            }
        };

        Ok(now < exp_time)
    }

    /// Verfify the [`JWT`] token and check if the token is expired
    pub fn validate(&self, public_key: impl VerifyFromKey) -> Result<bool, Error> {
        let algorithm = self.header.alg;

        let signature = match &self.signature {
            Some(val) => val.clone(),
            None => return Err(Error::JWT_NO_SIGNATURE_FOUND),
        };

        let verified = match verify(
            format!(
                "{}.{}",
                self.header.to_base64_encoded(),
                self.payload.to_base64_encoded()
            ),
            signature.0,
            public_key,
            algorithm,
        ) {
            Ok(val) => val,
            Err(error) => return Err(error),
        };

        if !verified {
            return Ok(false);
        }

        let exp = match self.payload.0.get("exp") {
            Some(val) => match val.as_i64() {
                Some(val) => val,
                None => return Err(Error::JWT_PAYLOAD_FIELD_EXP_IDENTIFICATION_ERROR),
            },
            None => return Err(Error::JWT_PAYLOAD_MISSING_FIELD_EXP),
        };

        Self::check_if_expired(exp)
    }

    /// Verfify the [`JWT`] token from signature and check if the token is expired. If it's
    /// a valid jwt token string returns the JWT content.
    pub fn validate_token(
        token_str: &str,
        public_key: impl VerifyFromKey,
    ) -> Result<(Self, bool), Error> {
        let token = match Self::from_token(token_str) {
            Ok(val) => val,
            Err(error) => return Err(error),
        };

        let verified = match token.validate(public_key) {
            Ok(val) => val,
            Err(error) => return Err(error),
        };

        Ok((token, verified))
    }
}
