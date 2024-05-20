#[cfg(feature = "wasm")]
use std::str::FromStr;

#[cfg(feature = "wasm")]
use did_crypto::{
    algorithms::Algorithm,
    crypto::rsa::{RsaSigningKey, RsaVerifyingKey},
    log,
    signer::sign,
    verifier::verify,
};

#[cfg(feature = "wasm")]
use rsa::BigUint;

#[cfg(feature = "wasm")]
use wasm_bindgen_test::wasm_bindgen_test;

use wasm_bindgen_test::wasm_bindgen_test_configure;

wasm_bindgen_test_configure!(run_in_browser);

#[cfg(feature = "wasm")]
const PRIVATE_KEY: &'static str = "-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----";

#[cfg(feature = "wasm")]
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

#[cfg(feature = "wasm")]
const RSA256_CONTENT: &'static str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
#[cfg(feature = "wasm")]
const RSA384_CONTENT: &'static str = "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
#[cfg(feature = "wasm")]
const RSA512_CONTENT: &'static str = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
#[cfg(feature = "wasm")]
const PS256_CONTENT: &'static str = "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
#[cfg(feature = "wasm")]
const PS384_CONTENT: &'static str = "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
#[cfg(feature = "wasm")]
const PS512_CONTENT: &'static str = "eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";

#[cfg(feature = "wasm")]
fn get_private_key_components() -> [String; 5] {
    [String::from("536550780935187793573023318343446459259542538879995231584016007257111911603970821055545968718198303841489402250878362539120980619733287239531781900079897965987123890474441186759253316122723473081455490719533731018449706321152542797433703848799567704304470761927301969275755990616693988948260553130346291862875010319133082939613528034630324957354038884492926448683520947947305884666088808693660928908043228102275915534028330632994788104709541005735594360358226453534095947669454162018816697611405454184446966819523334496881020339027881967142832226393967832068288086102269001070830566215647536901949454313262322216949941108645105400808645623703093546126762981032142944691429286262746025504176426847392511811456219663267319463808012657855399173847444188252738469512542809816584645652752227979530617831200866170417461268137584640425451421360455704625846464849056719153384552363760488269358528394846858267767995487547269402147995512867485238029248524858771651579644139140243002226864690991158074660651707936877066959162281473166002774157363097756886269716036429227017207371328233631775982529275127521030645009005037766949820394758918681143007320456357478893819321458003713875978976894193966913131227778129583065389362747014692747178198493") ,
     String::from("65537"),
     String::from("185795557052400198168152206943957977118819268159095042274862432956847242350741013672193725896681146640504760588391802485051368451168457827089037619061189929964932626919556407713421346050156194182073499037018760268744337324751450421059256223883567900292745463954379829573279314754341110902113691391734115805363161026327207291020177994383334522211766764494598056463125019343518314030428909234385783918078841243161109405820207445949367857062092002749036092802075028403844750849300284615637367221466276717912621343702985383405066993818739847144962914777678349344000027862198341552122142754442608029858567163360775445801011558574731015631825763435531303711774780743358489893391559824762970768150544197667634240304854093749872413482146326272376215631184409105598183340160136572566385432232702541342397532458346290767552471348580680752647268282303394743153390167486442161716136571787218570898275622718127417966379220953092380712108537394791382802538206345546237071551888054631218820054042839340888113823739086953611302812644870751537883296679783496860314045227727098712827806999698482915019415114670846166561591293049916017594108619336242401748002552675287104587037534938485233437321456426682149474752299287525418752921096179921566861862249") ,
     String::from("27815700726446278050654705666612246855318042400730742797426687327521924330127866544664187578765786678892149123724523045951947135451512527572968656406989944652673326429470439634725218797686907550451360612348596081735243414034380961903717184919852570288656142852814016204844700256442265673410536939922508300688016896415027400780406378980715943340495101074173940402091635114168408821752184478907329045051683346019203501475920168682226816212645684380924354553563622522800928709866795069252369302214663213879939466609994823077268270280161319429170117399220225084618311699411382779397828081300939695799363868657021256828467") ,
     String::from("19289493592554095988242185299717375167035265344339966821572440691667621783277253406949359716917050022577823083890506144922680848727820717075779274921627990541155278987134624061015240202481243212780317555555420633209258874538113067219220238096549320718596383716392703803181822462191952069794477195748438099997316397507028521746234754221898051113898404359354953868882710151433161336151727471799184517850795616954652985379423510750337004781501403377333691519570005957084508454121956012597935879230420822171833780656297217816769234870818456855971428413451668706038485119237471387925771040326129888055765258333261506728879") 
    ]
}

#[cfg(feature = "wasm")]
#[wasm_bindgen_test]
pub fn test_rsa256_signing_and_verifying() {
    let sig_result = sign(
        String::from(RSA256_CONTENT),
        RsaSigningKey::from_pem(PRIVATE_KEY),
        Algorithm::RS256,
    );

    let signature = match sig_result {
        Ok(val) => val,
        Err(error) => {
            log::error(error.to_string().as_str());
            assert!(false);
            return;
        }
    };

    match verify(
        String::from(RSA256_CONTENT),
        String::from(signature),
        RsaVerifyingKey::from_pem(PUBLIC_KEY),
        Algorithm::RS256,
    ) {
        Ok(val) => assert!(val),
        Err(error) => {
            log::error(error.to_string().as_str());
            assert!(false);
            return;
        }
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen_test]
pub fn test_rsa384_signing_and_verifying() {
    let sig_result = sign(
        String::from(RSA384_CONTENT),
        RsaSigningKey::from_pem(PRIVATE_KEY),
        Algorithm::RS384,
    );

    let signature = match sig_result {
        Ok(val) => val,
        Err(error) => {
            log::error(error.to_string().as_str());
            assert!(false);
            return;
        }
    };

    match verify(
        String::from(RSA384_CONTENT),
        String::from(signature),
        RsaVerifyingKey::from_pem(PUBLIC_KEY),
        Algorithm::RS384,
    ) {
        Ok(val) => assert!(val),
        Err(error) => {
            log::error(error.to_string().as_str());
            assert!(false);
            return;
        }
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen_test]
pub fn test_rsa512_signing_and_verifying() {
    let sig_result = sign(
        String::from(RSA512_CONTENT),
        RsaSigningKey::from_pem(PRIVATE_KEY),
        Algorithm::RS512,
    );

    let signature = match sig_result {
        Ok(val) => val,
        Err(error) => {
            log::error(error.to_string().as_str());
            assert!(false);
            return;
        }
    };

    match verify(
        String::from(RSA512_CONTENT),
        String::from(signature),
        RsaVerifyingKey::from_pem(PUBLIC_KEY),
        Algorithm::RS512,
    ) {
        Ok(val) => assert!(val),
        Err(error) => {
            log::error(error.to_string().as_str());
            assert!(false);
            return;
        }
    };
}

#[cfg(feature = "wasm")]
#[wasm_bindgen_test]
pub fn test_ps256_signing_and_verifying() {
    let sig_result = sign(
        String::from(PS256_CONTENT),
        RsaSigningKey::from_pem(PRIVATE_KEY),
        Algorithm::PS256,
    );

    let signature = match sig_result {
        Ok(val) => val,
        Err(error) => {
            log::error(error.to_string().as_str());
            assert!(false);
            return;
        }
    };

    match verify(
        String::from(PS256_CONTENT),
        String::from(signature),
        RsaVerifyingKey::from_pem(PUBLIC_KEY),
        Algorithm::PS256,
    ) {
        Ok(val) => assert!(val),
        Err(error) => {
            log::error(error.to_string().as_str());
            assert!(false);
            return;
        }
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen_test]
pub fn test_ps384_signing_and_verifying() {
    let sig_result = sign(
        String::from(PS384_CONTENT),
        RsaSigningKey::from_pem(PRIVATE_KEY),
        Algorithm::PS384,
    );

    let signature = match sig_result {
        Ok(val) => val,
        Err(error) => {
            log::error(error.to_string().as_str());
            assert!(false);
            return;
        }
    };

    match verify(
        String::from(PS384_CONTENT),
        String::from(signature),
        RsaVerifyingKey::from_pem(PUBLIC_KEY),
        Algorithm::PS384,
    ) {
        Ok(val) => assert!(val),
        Err(error) => {
            log::error(error.to_string().as_str());
            assert!(false);
            return;
        }
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen_test]
pub fn test_ps512_signing_and_verifying() {
    let sig_result = sign(
        String::from(PS512_CONTENT),
        RsaSigningKey::from_pem(PRIVATE_KEY),
        Algorithm::PS512,
    );

    let signature = match sig_result {
        Ok(val) => val,
        Err(error) => {
            log::error(error.to_string().as_str());
            assert!(false);
            return;
        }
    };

    match verify(
        String::from(PS512_CONTENT),
        String::from(signature),
        RsaVerifyingKey::from_pem(PUBLIC_KEY),
        Algorithm::PS512,
    ) {
        Ok(val) => assert!(val),
        Err(error) => {
            log::error(error.to_string().as_str());
            assert!(false);
            return;
        }
    }
}

/* --------------------------------------------------------------------------------- */

#[cfg(feature = "wasm")]
#[wasm_bindgen_test]
pub fn test_rsa256_component_signing_and_verifying() {
    let private_components = get_private_key_components();

    let sig_result = sign(
        String::from(RSA256_CONTENT),
        RsaSigningKey::from_components(
            private_components[0].clone(),
            private_components[1].clone(),
            private_components[2].clone(),
            private_components[3].clone(),
            private_components[4].clone(),
        ),
        Algorithm::RS256,
    );

    let signature = match sig_result {
        Ok(val) => val,
        Err(error) => {
            log::error(error.to_string().as_str());
            assert!(false);
            return;
        }
    };

    match verify(
        String::from(RSA256_CONTENT),
        String::from(signature),
        RsaVerifyingKey::from_pem(PUBLIC_KEY),
        Algorithm::RS256,
    ) {
        Ok(val) => assert!(val),
        Err(error) => {
            log::error(error.to_string().as_str());
            assert!(false);
            return;
        }
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen_test]
pub fn test_rsa384_component_signing_and_verifying() {
    let private_components = get_private_key_components();

    let sig_result = sign(
        String::from(RSA384_CONTENT),
        RsaSigningKey::from_components(
            private_components[0].clone(),
            private_components[1].clone(),
            private_components[2].clone(),
            private_components[3].clone(),
            private_components[4].clone(),
        ),
        Algorithm::RS384,
    );

    let signature = match sig_result {
        Ok(val) => val,
        Err(error) => {
            log::error(error.to_string().as_str());
            assert!(false);
            return;
        }
    };

    match verify(
        String::from(RSA384_CONTENT),
        String::from(signature),
        RsaVerifyingKey::from_pem(PUBLIC_KEY),
        Algorithm::RS384,
    ) {
        Ok(val) => assert!(val),
        Err(error) => {
            log::error(error.to_string().as_str());
            assert!(false);
            return;
        }
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen_test]
pub fn test_rsa512_component_signing_and_verifying() {
    let private_components = get_private_key_components();

    let sig_result = sign(
        String::from(RSA512_CONTENT),
        RsaSigningKey::from_components(
            private_components[0].clone(),
            private_components[1].clone(),
            private_components[2].clone(),
            private_components[3].clone(),
            private_components[4].clone(),
        ),
        Algorithm::RS512,
    );

    let signature = match sig_result {
        Ok(val) => val,
        Err(error) => {
            log::error(error.to_string().as_str());
            assert!(false);
            return;
        }
    };

    match verify(
        String::from(RSA512_CONTENT),
        String::from(signature),
        RsaVerifyingKey::from_pem(PUBLIC_KEY),
        Algorithm::RS512,
    ) {
        Ok(val) => assert!(val),
        Err(error) => {
            log::error(error.to_string().as_str());
            assert!(false);
            return;
        }
    };
}

#[cfg(feature = "wasm")]
#[wasm_bindgen_test]
pub fn test_ps256_component_signing_and_verifying() {
    let private_components = get_private_key_components();

    let sig_result = sign(
        String::from(PS256_CONTENT),
        RsaSigningKey::from_components(
            private_components[0].clone(),
            private_components[1].clone(),
            private_components[2].clone(),
            private_components[3].clone(),
            private_components[4].clone(),
        ),
        Algorithm::PS256,
    );

    let signature = match sig_result {
        Ok(val) => val,
        Err(error) => {
            log::error(error.to_string().as_str());
            assert!(false);
            return;
        }
    };

    match verify(
        String::from(PS256_CONTENT),
        String::from(signature),
        RsaVerifyingKey::from_pem(PUBLIC_KEY),
        Algorithm::PS256,
    ) {
        Ok(val) => assert!(val),
        Err(error) => {
            log::error(error.to_string().as_str());
            assert!(false);
            return;
        }
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen_test]
pub fn test_ps384_component_signing_and_verifying() {
    let private_components = get_private_key_components();

    let sig_result = sign(
        String::from(PS384_CONTENT),
        RsaSigningKey::from_components(
            private_components[0].clone(),
            private_components[1].clone(),
            private_components[2].clone(),
            private_components[3].clone(),
            private_components[4].clone(),
        ),
        Algorithm::PS384,
    );

    let signature = match sig_result {
        Ok(val) => val,
        Err(error) => {
            log::error(error.to_string().as_str());
            assert!(false);
            return;
        }
    };

    match verify(
        String::from(PS384_CONTENT),
        String::from(signature),
        RsaVerifyingKey::from_pem(PUBLIC_KEY),
        Algorithm::PS384,
    ) {
        Ok(val) => assert!(val),
        Err(error) => {
            log::error(error.to_string().as_str());
            assert!(false);
            return;
        }
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen_test]
pub fn test_ps512_component_signing_and_verifying() {
    let private_components = get_private_key_components();

    let sig_result = sign(
        String::from(PS512_CONTENT),
        RsaSigningKey::from_components(
            private_components[0].clone(),
            private_components[1].clone(),
            private_components[2].clone(),
            private_components[3].clone(),
            private_components[4].clone(),
        ),
        Algorithm::PS512,
    );

    let signature = match sig_result {
        Ok(val) => val,
        Err(error) => {
            log::error(error.to_string().as_str());
            assert!(false);
            return;
        }
    };

    match verify(
        String::from(PS512_CONTENT),
        String::from(signature),
        RsaVerifyingKey::from_pem(PUBLIC_KEY),
        Algorithm::PS512,
    ) {
        Ok(val) => assert!(val),
        Err(error) => {
            log::error(error.to_string().as_str());
            assert!(false);
            return;
        }
    }
}
