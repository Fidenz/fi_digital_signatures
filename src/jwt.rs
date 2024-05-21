#[cfg(not(feature = "wasm"))]
use crate::crypto::{SignFromKey, VerifyFromKey};
use crate::{algorithms::Algorithm, errors::Error, log, signer::sign, verifier::verify};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Utc};
#[cfg(feature = "wasm")]
use js_sys::Object;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

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
#[cfg(feature = "wasm")]
#[derive(Serialize, Deserialize, Clone)]
#[wasm_bindgen]
pub struct Header {
    typ: String,
    alg: Algorithm,
    kid: String,
}

#[cfg(not(feature = "wasm"))]
#[derive(Serialize, Deserialize, Clone)]
pub struct Header {
    pub typ: String,
    pub alg: Algorithm,
    pub kid: String,
}

#[cfg(not(feature = "wasm"))]
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

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl Header {
    /// Create JWT header instance
    #[wasm_bindgen(constructor)]
    pub fn new(kid: String, alg: Algorithm) -> Self {
        Header {
            kid,
            alg,
            typ: String::from("JWT"),
        }
    }

    #[wasm_bindgen(getter)]
    pub fn typ(&self) -> String {
        self.typ.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_typ(&mut self, typ: String) {
        self.typ = typ;
    }

    #[wasm_bindgen(getter)]
    pub fn kid(&self) -> String {
        self.kid.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_kid(&mut self, kid: String) {
        self.kid = kid;
    }

    #[wasm_bindgen(getter)]
    pub fn alg(&self) -> Algorithm {
        self.alg.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_alg(&mut self, alg: Algorithm) {
        self.alg = alg;
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
#[cfg(feature = "wasm")]
#[derive(Serialize, Deserialize)]
#[wasm_bindgen]
pub struct Payload(Value);

#[cfg(not(feature = "wasm"))]
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

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl Payload {
    #[wasm_bindgen(js_name = "fromObject")]
    pub fn from_object(value: Object) -> Result<Payload, Error> {
        let json_string = match js_sys::JSON::stringify(&value) {
            Ok(val) => match val.as_string() {
                Some(v) => v,
                None => {
                    log::error("No string content found in js value");
                    return Err(Error::JSON_DESERIALIZATION_FAILED);
                }
            },
            Err(error) => {
                log::error(error.as_string().unwrap().as_str());
                return Err(Error::JSON_DESERIALIZATION_FAILED);
            }
        };
        Ok(Payload(match serde_json::from_str(json_string.as_str()) {
            Ok(val) => val,
            Err(_error) => {
                // log::error(error.as_string().unwrap().as_str());
                return Err(Error::JSON_DESERIALIZATION_FAILED);
            }
        }))
    }
}

impl FromBase64Encoded for Payload {}
impl Base64Encode for Payload {}

/// JWT token signature
#[cfg(not(feature = "wasm"))]
#[derive(Serialize, Deserialize, Clone)]
pub struct Signature(String);

#[cfg(feature = "wasm")]
#[derive(Serialize, Deserialize, Clone)]
#[wasm_bindgen]
pub struct Signature(String);

impl ToString for Signature {
    fn to_string(&self) -> String {
        self.0.clone()
    }
}

/// JWT token object
#[cfg(feature = "wasm")]
#[derive(Serialize, Deserialize)]
#[wasm_bindgen]
pub struct JWT {
    header: Header,
    payload: Payload,
    signature: Option<Signature>,
}

#[cfg(not(feature = "wasm"))]
#[derive(Serialize, Deserialize)]
pub struct JWT {
    header: Header,
    payload: Payload,
    signature: Option<Signature>,
}

#[cfg(not(feature = "wasm"))]
impl JWT {
    /// Create instance of [`JWT`]
    pub fn new(header: Header, payload: Payload, signature: Option<Signature>) -> JWT {
        JWT {
            header,
            payload,
            signature,
        }
    }

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
    pub fn from_token(token: &str) -> Result<JWT, Error> {
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
    ) -> Result<(JWT, bool), Error> {
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

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl JWT {
    /// Create instance of [`JWT`]
    #[wasm_bindgen(constructor)]
    pub fn new(header: Header, payload: Payload, signature: Option<Signature>) -> JWT {
        JWT {
            header,
            payload,
            signature,
        }
    }

    /// Retrive jwt token from [`JWT`] token object
    #[wasm_bindgen(js_name = "toToken")]
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
    #[wasm_bindgen]
    pub fn sign(&mut self, private_key: js_sys::Object) -> Result<(), String> {
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
            Err(error) => Err(error.to_string()),
        }
    }

    /// Create [`JWT`] token instance from JWT token string
    #[wasm_bindgen(js_name = "fromToken")]
    pub fn from_token(token: &str) -> Result<JWT, String> {
        let token_content: Vec<&str> = token.split(".").collect();

        let header = match Header::from_base64_encoded(token_content[0]) {
            Ok(val) => val,
            Err(error) => return Err(error.to_string()),
        };

        let payload = match Payload::from_base64_encoded(token_content[1]) {
            Ok(val) => val,
            Err(error) => return Err(error.to_string()),
        };

        let signature: Signature = Signature(String::from(token_content[2]));

        Ok(JWT {
            header,
            payload,
            signature: Some(signature),
        })
    }

    fn check_if_expired(timestamp_secs: i64) -> Result<bool, String> {
        let now = Utc::now();
        let exp_time = match DateTime::from_timestamp_millis(timestamp_secs * 1000) {
            Some(val) => val,
            None => {
                return Err(Error::FAILED_TO_CONVERT_TIMESTAMP_TO_DATETTIME.to_string());
            }
        };

        Ok(now < exp_time)
    }

    /// Verfify the [`JWT`] token and check if the token is expired
    #[wasm_bindgen]
    pub fn validate(&self, public_key: js_sys::Object) -> Result<bool, String> {
        let algorithm = self.header.alg;

        let signature = match &self.signature {
            Some(val) => val.clone(),
            None => return Err(Error::JWT_NO_SIGNATURE_FOUND.to_string()),
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
            Err(error) => return Err(error.to_string()),
        };

        if !verified {
            return Ok(false);
        }

        let exp = match self.payload.0.get("exp") {
            Some(val) => match val.as_i64() {
                Some(val) => val,
                None => return Err(Error::JWT_PAYLOAD_FIELD_EXP_IDENTIFICATION_ERROR.to_string()),
            },
            None => return Err(Error::JWT_PAYLOAD_MISSING_FIELD_EXP.to_string()),
        };

        Self::check_if_expired(exp)
    }

    /// Verfify the [`JWT`] token from signature and check if the token is expired. If it's
    /// a valid jwt token string returns the JWT content.
    #[wasm_bindgen]
    pub fn validate_token(
        token_str: &str,
        public_key: js_sys::Object,
    ) -> Result<wasm_bindgen::JsValue, String> {
        let token = match Self::from_token(token_str) {
            Ok(val) => val,
            Err(error) => return Err(error.to_string()),
        };

        let verified = match token.validate(public_key) {
            Ok(val) => val,
            Err(error) => return Err(error.to_string()),
        };

        if verified {
            let js_str = match serde_json::to_string(&token) {
                Ok(val) => val,
                Err(error) => {
                    log::error(error.to_string().as_str());
                    return Err(Error::JSON_DESERIALIZATION_FAILED.to_string());
                }
            };

            let js_obj = match js_sys::JSON::parse(js_str.as_str()) {
                Ok(val) => val,
                Err(error) => return Err(error.as_string().unwrap()),
            };

            Ok(js_obj)
        } else {
            Ok(wasm_bindgen::JsValue::UNDEFINED)
        }
    }
}
