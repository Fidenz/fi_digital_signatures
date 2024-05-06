use did_crypto::{algorithms::Algorithm, signer::sign, verifier::verify};

const PUBLIC_KEY_256: &'static str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
-----END PUBLIC KEY-----";
const PRIVATE_KEY_256: &'static str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
-----END PRIVATE KEY-----";

const PUBLIC_KEY_384: &'static str = "-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEC1uWSXj2czCDwMTLWV5BFmwxdM6PX9p+
Pk9Yf9rIf374m5XP1U8q79dBhLSIuaojsvOT39UUcPJROSD1FqYLued0rXiooIii
1D3jaW6pmGVJFhodzC31cy5sfOYotrzF
-----END PUBLIC KEY-----";
const PRIVATE_KEY_384: &'static str = "-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCAHpFQ62QnGCEvYh/p
E9QmR1C9aLcDItRbslbmhen/h1tt8AyMhskeenT+rAyyPhGhZANiAAQLW5ZJePZz
MIPAxMtZXkEWbDF0zo9f2n4+T1h/2sh/fviblc/VTyrv10GEtIi5qiOy85Pf1RRw
8lE5IPUWpgu553SteKigiKLUPeNpbqmYZUkWGh3MLfVzLmx85ii2vMU=
-----END PRIVATE KEY-----";

const PUBLIC_KEY_512: &'static str = "-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBgc4HZz+/fBbC7lmEww0AO3NK9wVZ
PDZ0VEnsaUFLEYpTzb90nITtJUcPUbvOsdZIZ1Q8fnbquAYgxXL5UgHMoywAib47
6MkyyYgPk0BXZq3mq4zImTRNuaU9slj9TVJ3ScT3L1bXwVuPJDzpr5GOFpaj+WwM
Al8G7CqwoJOsW7Kddns=
-----END PUBLIC KEY-----";
const PRIVATE_KEY_512: &'static str = "-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBiyAa7aRHFDCh2qga
9sTUGINE5jHAFnmM8xWeT/uni5I4tNqhV5Xx0pDrmCV9mbroFtfEa0XVfKuMAxxf
Z6LM/yKhgYkDgYYABAGBzgdnP798FsLuWYTDDQA7c0r3BVk8NnRUSexpQUsRilPN
v3SchO0lRw9Ru86x1khnVDx+duq4BiDFcvlSAcyjLACJvjvoyTLJiA+TQFdmrear
jMiZNE25pT2yWP1NUndJxPcvVtfBW48kPOmvkY4WlqP5bAwCXwbsKrCgk6xbsp12
ew==
-----END PRIVATE KEY-----";

const PUBLIC_KEY_256K: &'static str = "-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEp8WeJ3LpufxgnjVM0H54tyRqhq9ozrG7
MkCJ7v5hynCxxaf3HwdhS5tjupHzJ6RCL5VmHHTZoB+4qEySB+Yi9g==
-----END PUBLIC KEY-----
";

const PRIVATE_KEY_256K: &'static str = "-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIESaKnClEXVfXLKpW4bpUkga/sPcS0Ew3gAEpAMZ31EDoAcGBSuBBAAK
oUQDQgAEp8WeJ3LpufxgnjVM0H54tyRqhq9ozrG7MkCJ7v5hynCxxaf3HwdhS5tj
upHzJ6RCL5VmHHTZoB+4qEySB+Yi9g==
-----END EC PRIVATE KEY-----
";

const EC256_CONTENT: &'static str = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
const EC384_CONTENT: &'static str = "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
const EC512_CONTENT: &'static str = "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
const EC256K_CONTENT: &'static str = "eyJhbGciOiJFUzI1Ni1LIiwidHlwIjoiSldUIn0=.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0=";

#[test]
pub fn ec256_test() {
    let sig_result = sign(
        String::from(EC256_CONTENT),
        String::from(PRIVATE_KEY_256),
        Algorithm::ES256,
    );

    let signature = match sig_result {
        Ok(val) => val,
        Err(error) => {
            eprintln!("{}", error);
            panic!()
        }
    };

    assert!(match verify(
        String::from(EC256_CONTENT),
        signature,
        String::from(PUBLIC_KEY_256),
        Algorithm::ES256
    ) {
        Ok(val) => val,
        Err(error) => {
            println!("{}", error.to_string());
            panic!()
        }
    })
}

#[test]
pub fn ec384_test() {
    let sig_result = sign(
        String::from(EC384_CONTENT),
        String::from(PRIVATE_KEY_384),
        Algorithm::ES384,
    );

    let signature = match sig_result {
        Ok(val) => val,
        Err(error) => {
            eprintln!("{}", error);
            panic!()
        }
    };

    assert!(match verify(
        String::from(EC384_CONTENT),
        signature,
        String::from(PUBLIC_KEY_384),
        Algorithm::ES384
    ) {
        Ok(val) => val,
        Err(error) => {
            println!("{}", error.to_string());
            panic!()
        }
    })
}

#[test]
pub fn ec512_test() {
    let sig_result = sign(
        String::from(EC512_CONTENT),
        String::from(PRIVATE_KEY_512),
        Algorithm::ES512,
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
        String::from(EC512_CONTENT),
        signature,
        String::from(PUBLIC_KEY_512),
        Algorithm::ES512
    ) {
        Ok(val) => val,
        Err(error) => {
            println!("{}", error.to_string());
            panic!()
        }
    })
}

#[test]
pub fn ec256k_test() {
    let sig_result = sign(
        String::from(EC256K_CONTENT),
        String::from(PRIVATE_KEY_256K),
        Algorithm::ES256K,
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
        String::from(EC256K_CONTENT),
        signature,
        String::from(PUBLIC_KEY_256K),
        Algorithm::ES256K
    ) {
        Ok(val) => val,
        Err(error) => {
            println!("{}", error.to_string());
            panic!()
        }
    })
}
