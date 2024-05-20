use chrono::Utc;
use did_crypto::{
    algorithms::Algorithm,
    crypto::ecdsa::_512::{P512SigningKey, P512VerifyingKey},
    jwt::{Header, Payload, JWT},
};
use serde_json::{json, Value};

const PUBLIC_KEY: &'static str = "-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBgc4HZz+/fBbC7lmEww0AO3NK9wVZ
PDZ0VEnsaUFLEYpTzb90nITtJUcPUbvOsdZIZ1Q8fnbquAYgxXL5UgHMoywAib47
6MkyyYgPk0BXZq3mq4zImTRNuaU9slj9TVJ3ScT3L1bXwVuPJDzpr5GOFpaj+WwM
Al8G7CqwoJOsW7Kddns=
-----END PUBLIC KEY-----";

const PRIVATE_KEY: &'static str = "-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBiyAa7aRHFDCh2qga
9sTUGINE5jHAFnmM8xWeT/uni5I4tNqhV5Xx0pDrmCV9mbroFtfEa0XVfKuMAxxf
Z6LM/yKhgYkDgYYABAGBzgdnP798FsLuWYTDDQA7c0r3BVk8NnRUSexpQUsRilPN
v3SchO0lRw9Ru86x1khnVDx+duq4BiDFcvlSAcyjLACJvjvoyTLJiA+TQFdmrear
jMiZNE25pT2yWP1NUndJxPcvVtfBW48kPOmvkY4WlqP5bAwCXwbsKrCgk6xbsp12
ew==
-----END PRIVATE KEY-----";

#[cfg(not(feature = "wasm"))]
#[test]
pub fn test_jwt_validate_success() {
    let now = Utc::now().timestamp_millis() / 1000;

    let payload_content: Value = json!(
        {
    "sub": "1234567890",
    "name": "John Doe",
    "admin": true,
    "iat": 151623902,
    "exp": now + 10
    }
    );

    let mut jwt = JWT::new(
        Header::new(String::from("id:129877"), Algorithm::ES512),
        Payload(payload_content),
        None,
    );

    match jwt.sign(P512SigningKey::from_pem(PRIVATE_KEY).unwrap()) {
        Ok(()) => {}
        Err(error) => {
            println!("{}", error);
            panic!()
        }
    };

    match jwt.to_token() {
        Ok(val) => val,
        Err(error) => {
            println!("{}", error);
            panic!()
        }
    };

    let validated = match jwt.validate(P512VerifyingKey::from_pem(PUBLIC_KEY).unwrap()) {
        Ok(val) => val,
        Err(error) => {
            println!("{}", error);
            panic!()
        }
    };

    assert!(validated);
}

pub fn test_jwt_validate_expire() {
    let now = Utc::now().timestamp_millis() / 1000;

    let payload_content: Value = json!(
        {
    "sub": "1234567890",
    "name": "John Doe",
    "admin": true,
    "iat": 151623902,
    "exp": now - 10
    }
    );

    let mut jwt = JWT::new(
        Header::new(String::from("id:129877"), Algorithm::ES512),
        Payload(payload_content),
        None,
    );

    match jwt.sign(P512SigningKey::from_pem(PRIVATE_KEY).unwrap()) {
        Ok(()) => {}
        Err(error) => {
            println!("{}", error);
            panic!()
        }
    };

    match jwt.to_token() {
        Ok(val) => val,
        Err(error) => {
            println!("{}", error);
            panic!()
        }
    };

    let validated = match jwt.validate(P512VerifyingKey::from_pem(PUBLIC_KEY).unwrap()) {
        Ok(val) => val,
        Err(error) => {
            println!("{}", error);
            panic!()
        }
    };

    assert!(!validated);
}
