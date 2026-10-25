//! Frozen signatures and JWKs emitted by Jacquard 3287244a with the old curve providers.
//! The fixture was captured before this dependency migration; do not regenerate it from this tree.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jacquard_oauth::{
    dpop,
    jose::{
        jws::RegisteredHeader,
        jwt::{Claims, RegisteredClaims, RegisteredClaimsAud},
        signing,
    },
    keyset::Keyset,
};
use jose_jwa::{Algorithm, Signing};
use jose_jwk::{Key, crypto};
use p256::ecdsa::signature::Verifier;
use serde_json::Value;

fn frozen() -> Value {
    serde_json::from_str(include_str!("fixtures/crypto-before-refresh.json")).unwrap()
}

fn header(alg: Signing) -> jacquard_oauth::jose::Header<&'static str> {
    let mut header = RegisteredHeader::from(Algorithm::Signing(alg));
    header.kid = Some("compat-fixed-key");
    header.typ = Some("JWT");
    header.into()
}

fn claims() -> Claims<&'static str> {
    RegisteredClaims {
        iss: Some("did:plc:compat-test"),
        aud: Some(RegisteredClaimsAud::Single("https://example.test")),
        iat: Some(1_700_000_000),
        exp: Some(1_700_000_600),
        jti: Some("fixed-compatibility-jti".into()),
        ..Default::default()
    }
    .into()
}

#[test]
fn original_jwk_encoding_thumbprint_and_private_identity_survive() {
    let old = frozen();
    let p256 = p256::SecretKey::from_slice(&[1; 32]).unwrap();
    let p384 = p384::SecretKey::from_slice(&[2; 48]).unwrap();
    let p256_jwk = Key::from(&crypto::Key::from(p256.clone()));
    let p384_jwk = Key::from(&crypto::Key::from(p384.clone()));
    assert_eq!(
        serde_json::to_string(&p256_jwk).unwrap(),
        old["p256_jwk_json"]
    );
    assert_eq!(
        serde_json::to_string(&p384_jwk).unwrap(),
        old["p384_jwk_json"]
    );
    assert_eq!(dpop::jkt(&p256_jwk).unwrap().as_str(), old["p256_jkt"]);

    for (field, expected) in [
        ("p256_jwk_json", crypto::Key::from(p256)),
        ("p384_jwk_json", crypto::Key::from(p384)),
    ] {
        let retained: Key = serde_json::from_str(old[field].as_str().unwrap()).unwrap();
        let restored = crypto::Key::try_from(&retained).unwrap();
        assert_eq!(Key::from(&restored), Key::from(&expected));
    }
}

#[test]
fn signatures_keep_the_original_exact_bytes_for_all_supported_algorithms() {
    let actual = [
        (
            "ES256",
            signing::create_signed_jwt_es256(
                p256::ecdsa::SigningKey::from_slice(&[1; 32]).unwrap(),
                header(Signing::Es256),
                claims(),
            )
            .unwrap(),
        ),
        (
            "ES384",
            signing::create_signed_jwt_es384(
                p384::ecdsa::SigningKey::from_slice(&[2; 48]).unwrap(),
                header(Signing::Es384),
                claims(),
            )
            .unwrap(),
        ),
        (
            "ES256K",
            signing::create_signed_jwt_es256k(
                k256::ecdsa::SigningKey::from_slice(&[3; 32]).unwrap(),
                header(Signing::Es256K),
                claims(),
            )
            .unwrap(),
        ),
        (
            "EdDSA",
            signing::create_signed_jwt_eddsa(
                ed25519_dalek::SigningKey::from_bytes(&[4; 32]),
                header(Signing::EdDsa),
                claims(),
            )
            .unwrap(),
        ),
    ];
    for (algorithm, jwt) in actual {
        assert_eq!(
            jwt.as_str(),
            frozen()["signatures"][algorithm],
            "{algorithm}"
        );
    }
}

#[test]
fn retained_signatures_verify_and_mutated_signed_payloads_fail() {
    let old = frozen();
    for algorithm in ["ES256", "ES384", "ES256K", "EdDSA"] {
        let jwt = old["signatures"][algorithm].as_str().unwrap();
        let (message, signature) = jwt.rsplit_once('.').unwrap();
        let signature = URL_SAFE_NO_PAD.decode(signature).unwrap();
        let mut changed = message.as_bytes().to_vec();
        changed[0] ^= 1;
        match algorithm {
            "ES256" => {
                let key = p256::ecdsa::SigningKey::from_slice(&[1; 32]).unwrap();
                let sig = p256::ecdsa::Signature::from_slice(&signature).unwrap();
                key.verifying_key()
                    .verify(message.as_bytes(), &sig)
                    .unwrap();
                assert!(key.verifying_key().verify(&changed, &sig).is_err());
            }
            "ES384" => {
                let key = p384::ecdsa::SigningKey::from_slice(&[2; 48]).unwrap();
                let sig = p384::ecdsa::Signature::from_slice(&signature).unwrap();
                key.verifying_key()
                    .verify(message.as_bytes(), &sig)
                    .unwrap();
                assert!(key.verifying_key().verify(&changed, &sig).is_err());
            }
            "ES256K" => {
                let key = k256::ecdsa::SigningKey::from_slice(&[3; 32]).unwrap();
                let sig = k256::ecdsa::Signature::from_slice(&signature).unwrap();
                key.verifying_key()
                    .verify(message.as_bytes(), &sig)
                    .unwrap();
                assert!(key.verifying_key().verify(&changed, &sig).is_err());
            }
            "EdDSA" => {
                let key = ed25519_dalek::SigningKey::from_bytes(&[4; 32]);
                let sig = ed25519_dalek::Signature::from_slice(&signature).unwrap();
                key.verifying_key()
                    .verify(message.as_bytes(), &sig)
                    .unwrap();
                assert!(key.verifying_key().verify(&changed, &sig).is_err());
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn key_ids_public_projection_and_invalid_private_key_rejection_survive() {
    let old = frozen();
    let key: Key = serde_json::from_str(old["p256_jwk_json"].as_str().unwrap()).unwrap();
    let jwk = jose_jwk::Jwk {
        key,
        prm: jose_jwk::Parameters {
            kid: Some("retained-key-id".into()),
            ..Default::default()
        },
    };
    let set = Keyset::try_from(vec![jwk.clone()]).unwrap();
    let public = set.public_jwks();
    assert_eq!(public.keys[0].prm.kid.as_deref(), Some("retained-key-id"));
    let Key::Ec(ec) = &public.keys[0].key else {
        panic!("expected EC key")
    };
    assert!(ec.d.is_none());
    assert_eq!(
        dpop::jkt(&public.keys[0].key).unwrap(),
        dpop::jkt(&jwk.key).unwrap()
    );
    let jwt = set.create_jwt(&[Signing::Es256], claims()).unwrap();
    let encoded_header = jwt.split('.').next().unwrap();
    let header: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded_header).unwrap()).unwrap();
    assert_eq!(header["kid"], "retained-key-id");
    assert_eq!(header["alg"], "ES256");

    for invalid in [
        Vec::new(),
        vec![1; 31],
        vec![0; 32],
        vec![255; 32],
        vec![1; 33],
    ] {
        let mut bad = jwk.clone();
        let Key::Ec(ec) = &mut bad.key else {
            unreachable!()
        };
        ec.d = Some(invalid.into());
        let set = Keyset::try_from(vec![bad]).unwrap();
        assert!(set.create_jwt(&[Signing::Es256], claims()).is_err());
    }
}

#[test]
fn malformed_jwk_public_points_and_wrong_curve_are_rejected() {
    let old = frozen();
    let Key::Ec(mut ec) =
        serde_json::from_str::<Key>(old["p256_jwk_json"].as_str().unwrap()).unwrap()
    else {
        unreachable!()
    };
    ec.d = None;
    for (x, y) in [
        (vec![0; 32], vec![0; 32]),
        (vec![1; 31], vec![2; 32]),
        (vec![1; 32], vec![2; 33]),
    ] {
        let mut invalid = ec.clone();
        invalid.x = x.into();
        invalid.y = y.into();
        assert!(p256::PublicKey::try_from(&invalid).is_err());
    }
    ec.crv = jose_jwk::EcCurves::P384;
    assert!(p256::PublicKey::try_from(&ec).is_err());
}
