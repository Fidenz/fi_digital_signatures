#[cfg(feature = "wasm")]
use did_crypto::{
    algorithms::Algorithm,
    crypto::eddsa::{EDDSASigningKey, EDDSAVerifyingKey},
    signer::sign,
    verifier::verify,
};
#[cfg(feature = "wasm")]
use wasm_bindgen_test::wasm_bindgen_test;

use wasm_bindgen_test::wasm_bindgen_test_configure;

wasm_bindgen_test_configure!(run_in_browser);

#[cfg(feature = "wasm")]
const PRIVATE_KEY: &'static str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIKp/Jj0KGmcaTAbqIoAME5HdiXQXTwHQ5ahI/lG90bz4
-----END PRIVATE KEY-----
";

#[cfg(feature = "wasm")]
const PRIVATE_KEY_HEX: &'static str =
    "aa7f263d0a1a671a4c06ea22800c1391dd8974174f01d0e5a848fe51bdd1bcf8";

#[cfg(feature = "wasm")]
const PUBLIC_KEY: &'static str = "-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAe233GXWVDV6hWsCQxX1GL3PTpIZE+88sbV24OK3xNrU=
-----END PUBLIC KEY-----
";

#[cfg(feature = "wasm")]
const PUBLIC_KEY_HEX: &'static str =
    "7b6df71975950d5ea15ac090c57d462f73d3a48644fbcf2c6d5db838adf136b5";

#[cfg(feature = "wasm")]
const CONTENT: &'static str = "eyJhbGciOiJFRDI1NTE5IiwidHlwIjoiSldUIn0=.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0=";

#[cfg(feature = "wasm")]
#[wasm_bindgen_test]
pub fn eddsa_signing_and_verifying() {
    let sig_result = sign(
        String::from(CONTENT),
        EDDSASigningKey::from_pem(PRIVATE_KEY),
        Algorithm::EdDSA,
    );

    let signature = match sig_result {
        Ok(val) => val,
        Err(error) => {
            eprintln!("{}", error);
            assert!(false);
            return;
        }
    };

    assert!(match verify(
        String::from(CONTENT),
        signature,
        EDDSAVerifyingKey::from_pem(PUBLIC_KEY),
        Algorithm::EdDSA
    ) {
        Ok(val) => val,
        Err(error) => {
            println!("{}", error.to_string());
            assert!(false);
            return;
        }
    })
}

#[cfg(feature = "wasm")]
#[wasm_bindgen_test]
pub fn eddsa_hex_signing_and_verifying() {
    let sig_result = sign(
        String::from(CONTENT),
        EDDSASigningKey::from_bytes(hex::decode(PRIVATE_KEY_HEX).unwrap().as_mut_slice()),
        Algorithm::EdDSA,
    );

    let signature = match sig_result {
        Ok(val) => val,
        Err(error) => {
            eprintln!("{}", error);
            assert!(false);
            return;
        }
    };

    assert!(match verify(
        String::from(CONTENT),
        signature,
        EDDSAVerifyingKey::from_bytes(hex::decode(PUBLIC_KEY_HEX).unwrap().as_mut_slice()),
        Algorithm::EdDSA
    ) {
        Ok(val) => val,
        Err(error) => {
            println!("{}", error.to_string());
            assert!(false);
            return;
        }
    })
}
