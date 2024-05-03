use did_crypto_wasm::{algorithms::Algorithm, signer::sign, verifier::verify};

const PRIVATE_KEY: &'static str = "-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----";

const PUBLIC_KEY: &'static str = "-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAg4TeWkvIRLAfwH2DsPgZ
DNwQVasBzEy4EIFBbVBZOfuCxYk0NAU6vSuUjny9tIDyhnJ6UHdizJ377fgvJvR8
GTKJrz1dN3/D8H+0qZ6aQefLNRjBzfFW+mgJ8ICznyNPlSu5XikQ8pI8A2Kf64dP
Fy7QDd+oIm6BRKL+2Nwrepq4utjwXNKuzaGrZYzvJiJp3X3W5wAseV1nOfkTZzH2
JnRbtL8uLhbm9wEeXkvqeMFmfuHyq7FaNOBG8XWq8z6ki858+4fak0/EaeALWdZJ
Ec34v0hfV1IP2h5YIZPUfJbugIacusa5F+917U5ZPHciMIj8Myl0EdAk0ZyE6lwq
sgPHnt0uAzEVm04d9/1rOpFIQ3ux+OvzjZRq6sSUtDlUJsbLFc4ERk1xg9sg7gpG
W1o8pssz7Il4tIM1bo9DTVxqCq4MXDw8MasKH0Ods35caqIHBIayaDhDKm5cS7rt
XhW9Bfn5f171nYgBebE/v0MiNIfO3/5sHgsOFP1UtSHAtcS5fE70ywg5qKEh0JNU
/joWEHIAJ6qsUqpunthWHveAWWtH6U1oojZrs+7sEGRr81H4QPzLtwV+Cc/+dXbX
xUxxbn/5p50u1jBSI0IFFzQSculW1YMFXQX/2WK7SwusVbLTBfiQGT9rdX2Sb4+r
YtikMnhP7iJ5qVcWLlRgxd0CAwEAAQ==
-----END PUBLIC KEY-----";

const RSA256_CONTENT: &'static str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
const RSA384_CONTENT: &'static str = "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
const RSA512_CONTENT: &'static str = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
const PS256_CONTENT: &'static str = "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
const PS384_CONTENT: &'static str = "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
const PS512_CONTENT: &'static str = "eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";

#[test]
pub fn test_rsa256_signing_and_verifying() {
    let sig_result = sign(
        String::from(RSA256_CONTENT),
        String::from(PRIVATE_KEY),
        Algorithm::RS256,
    );

    let signature = match sig_result {
        Ok(val) => val,
        Err(error) => {
            eprintln!("{}", error);
            panic!()
        }
    };

    match verify(
        String::from(RSA256_CONTENT),
        String::from(signature),
        String::from(PUBLIC_KEY),
        Algorithm::RS256,
    ) {
        Ok(val) => assert!(val),
        Err(error) => {
            println!("{}", error.to_string());
        }
    }
}

#[test]
pub fn test_rsa384_signing_and_verifying() {
    let sig_result = sign(
        String::from(RSA384_CONTENT),
        String::from(PRIVATE_KEY),
        Algorithm::RS384,
    );

    let signature = match sig_result {
        Ok(val) => val,
        Err(error) => {
            eprintln!("{}", error);
            panic!()
        }
    };

    match verify(
        String::from(RSA384_CONTENT),
        String::from(signature),
        String::from(PUBLIC_KEY),
        Algorithm::RS384,
    ) {
        Ok(val) => assert!(val),
        Err(error) => {
            println!("{}", error.to_string());
        }
    }
}

#[test]
pub fn test_rsa512_signing_and_verifying() {
    let sig_result = sign(
        String::from(RSA512_CONTENT),
        String::from(PRIVATE_KEY),
        Algorithm::RS512,
    );

    let signature = match sig_result {
        Ok(val) => val,
        Err(error) => {
            eprintln!("{}", error);
            panic!()
        }
    };

    match verify(
        String::from(RSA512_CONTENT),
        String::from(signature),
        String::from(PUBLIC_KEY),
        Algorithm::RS512,
    ) {
        Ok(val) => assert!(val),
        Err(error) => {
            println!("{}", error.to_string());
        }
    };
}

#[test]
pub fn test_ps256_signing() {
    let sig_result = sign(
        String::from(PS256_CONTENT),
        String::from(PRIVATE_KEY),
        Algorithm::PS256,
    );

    let signature = match sig_result {
        Ok(val) => val,
        Err(error) => {
            eprintln!("{}", error);
            panic!()
        }
    };

    match verify(
        String::from(PS256_CONTENT),
        String::from(signature),
        String::from(PUBLIC_KEY),
        Algorithm::PS256,
    ) {
        Ok(val) => assert!(val),
        Err(error) => {
            println!("{}", error.to_string());
        }
    }
}

#[test]
pub fn test_ps384_signing() {
    let sig_result = sign(
        String::from(PS384_CONTENT),
        String::from(PRIVATE_KEY),
        Algorithm::PS384,
    );

    let signature = match sig_result {
        Ok(val) => val,
        Err(error) => {
            eprintln!("{}", error);
            panic!()
        }
    };

    match verify(
        String::from(PS384_CONTENT),
        String::from(signature),
        String::from(PUBLIC_KEY),
        Algorithm::PS384,
    ) {
        Ok(val) => assert!(val),
        Err(error) => {
            println!("{}", error.to_string());
        }
    }
}

#[test]
pub fn test_ps512_signing() {
    let sig_result = sign(
        String::from(PS512_CONTENT),
        String::from(PRIVATE_KEY),
        Algorithm::PS512,
    );

    let signature = match sig_result {
        Ok(val) => val,
        Err(error) => {
            eprintln!("{}", error);
            panic!()
        }
    };

    match verify(
        String::from(PS512_CONTENT),
        String::from(signature),
        String::from(PUBLIC_KEY),
        Algorithm::PS512,
    ) {
        Ok(val) => assert!(val),
        Err(error) => {
            println!("{}", error.to_string());
        }
    }
}
