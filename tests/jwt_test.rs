use std::str::FromStr;

use chrono::Utc;
use did_crypto::{
    algorithms::Algorithm,
    jwt::{Header, Payload, JWT},
};
use serde_json::Value;

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

#[test]
pub fn test_jwt_validate_success() {
    let now = Utc::now().timestamp_millis() / 1000;

    let payload_content: Value = Value::from_str(
        format!(
            "{{
        \"sub\": \"1234567890\",
        \"name\": \"John Doe\",
        \"admin\": true,
        \"iat\": 1516239022,
        \"exp\": {}
        }}",
            now + 10
        )
        .as_str(),
    )
    .unwrap();

    let mut jwt = JWT {
        header: Header::new(String::from("id:129877"), Algorithm::ES512),
        payload: Payload(payload_content),
        signature: None,
    };

    match jwt.sign(String::from(PRIVATE_KEY)) {
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

    let validated = match jwt.validate(String::from(PUBLIC_KEY)) {
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

    let payload_content: Value = Value::from_str(
        format!(
            "{{
        \"sub\": \"1234567890\",
        \"name\": \"John Doe\",
        \"admin\": true,
        \"iat\": 1516239022,
        \"exp\": {}
        }}",
            now - 10
        )
        .as_str(),
    )
    .unwrap();

    let mut jwt = JWT {
        header: Header::new(String::from("id:129877"), Algorithm::ES512),
        payload: Payload(payload_content),
        signature: None,
    };

    match jwt.sign(String::from(PRIVATE_KEY)) {
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

    let validated = match jwt.validate(String::from(PUBLIC_KEY)) {
        Ok(val) => val,
        Err(error) => {
            println!("{}", error);
            panic!()
        }
    };

    assert!(!validated);
}
