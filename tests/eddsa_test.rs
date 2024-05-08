use did_crypto::{
    algorithms::Algorithm,
    crypto::eddsa::{EDDSASigningKey, EDDSAVerifyingKey},
    signer::sign,
    verifier::verify,
};

const PRIVATE_KEY: &'static str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIKp/Jj0KGmcaTAbqIoAME5HdiXQXTwHQ5ahI/lG90bz4
-----END PRIVATE KEY-----
";

const PUBLIC_KEY: &'static str = "-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAe233GXWVDV6hWsCQxX1GL3PTpIZE+88sbV24OK3xNrU=
-----END PUBLIC KEY-----
";

const CONTENT: &'static str = "eyJhbGciOiJFRDI1NTE5IiwidHlwIjoiSldUIn0=.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0=";

#[test]
pub fn eddsa_signing_and_verifying() {
    let sig_result = sign(
        String::from(CONTENT),
        EDDSASigningKey::from_pem(PRIVATE_KEY).unwrap(),
        Algorithm::EdDSA,
    );

    let signature = match sig_result {
        Ok(val) => val,
        Err(error) => {
            eprintln!("{}", error);
            panic!()
        }
    };

    assert!(match verify(
        String::from(CONTENT),
        signature,
        EDDSAVerifyingKey::from_pem(PUBLIC_KEY).unwrap(),
        Algorithm::EdDSA
    ) {
        Ok(val) => val,
        Err(error) => {
            println!("{}", error.to_string());
            panic!()
        }
    })
}
