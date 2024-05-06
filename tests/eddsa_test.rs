use did_crypto::{algorithms::Algorithm, signer::sign, verifier::verify};

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
pub fn eddsa_test() {
    let sig_result = sign(
        String::from(CONTENT),
        String::from(PRIVATE_KEY),
        Algorithm::EdDSA,
    );

    let signature = match sig_result {
        Ok(val) => val,
        Err(error) => {
            eprintln!("{}", error);
            panic!()
        }
    };

    println!("{}", signature);

    assert!(match verify(
        String::from(CONTENT),
        signature,
        String::from(PUBLIC_KEY),
        Algorithm::EdDSA
    ) {
        Ok(val) => val,
        Err(error) => {
            println!("{}", error.to_string());
            panic!()
        }
    })
}
