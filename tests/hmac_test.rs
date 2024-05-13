use did_crypto::{
    algorithms::Algorithm,
    crypto::{hmac::HMACKey, SignFromKey, VerifyFromKey},
};

const PASS_KEY: &'static str = "password for testing purposes.";

const HMAC256_CONTENT: &'static str=  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";
const HMAC384_CONTENT: &'static str=  "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";
const HMAC512_CONTENT: &'static str=  "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";

#[test]
pub fn hmac256_signing_and_verifying() {
    let key = HMACKey::new(String::from(PASS_KEY));

    let sig = match key.sign(String::from(HMAC256_CONTENT), Algorithm::HS256) {
        Ok(val) => val,
        Err(_error) => panic!(),
    };

    assert!(key
        .verify(String::from(HMAC256_CONTENT), sig, Algorithm::HS256)
        .unwrap());
}

#[test]
pub fn hmac384_signing_and_verifying() {
    let key = HMACKey::new(String::from(PASS_KEY));

    let sig = match key.sign(String::from(HMAC384_CONTENT), Algorithm::HS384) {
        Ok(val) => val,
        Err(_error) => panic!(),
    };

    assert!(key
        .verify(String::from(HMAC384_CONTENT), sig, Algorithm::HS384)
        .unwrap());
}

#[test]
pub fn hmac512_signing_and_verifying() {
    let key = HMACKey::new(String::from(PASS_KEY));

    let sig = match key.sign(String::from(HMAC512_CONTENT), Algorithm::HS512) {
        Ok(val) => val,
        Err(_error) => panic!(),
    };

    assert!(key
        .verify(String::from(HMAC512_CONTENT), sig, Algorithm::HS512)
        .unwrap());
}
