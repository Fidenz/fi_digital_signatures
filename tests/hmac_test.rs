use fi_digital_signatures::{
    algorithms::Algorithm, crypto::hmac::HMACKey, signer::sign, verifier::verify,
};

const PASS_KEY: &'static str = "password for testing purposes.";

const HMAC256_CONTENT: &'static str=  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";
const HMAC384_CONTENT: &'static str=  "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";
const HMAC512_CONTENT: &'static str=  "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";

#[cfg(not(feature = "wasm"))]
#[test]
pub fn hmac256_signing_and_verifying() {
    let key = HMACKey::new(String::from(PASS_KEY));

    let sig = match sign(String::from(HMAC256_CONTENT), key.clone(), Algorithm::HS256) {
        Ok(val) => val,
        Err(_error) => panic!(),
    };

    assert!(verify(String::from(HMAC256_CONTENT), sig, key, Algorithm::HS256).unwrap());
}

#[cfg(not(feature = "wasm"))]
#[test]
pub fn hmac384_signing_and_verifying() {
    let key = HMACKey::new(String::from(PASS_KEY));

    let sig = match sign(String::from(HMAC384_CONTENT), key.clone(), Algorithm::HS384) {
        Ok(val) => val,
        Err(_error) => panic!(),
    };

    assert!(verify(String::from(HMAC384_CONTENT), sig, key, Algorithm::HS384).unwrap());
}

#[cfg(not(feature = "wasm"))]
#[test]
pub fn hmac512_signing_and_verifying() {
    let key = HMACKey::new(String::from(PASS_KEY));

    let sig = match sign(String::from(HMAC512_CONTENT), key.clone(), Algorithm::HS512) {
        Ok(val) => val,
        Err(_error) => panic!(),
    };

    assert!(verify(String::from(HMAC512_CONTENT), sig, key, Algorithm::HS512).unwrap());
}
