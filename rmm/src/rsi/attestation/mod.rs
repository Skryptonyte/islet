pub mod claims;

use alloc::{boxed::Box, string::String, vec, vec::Vec};
use ciborium::{ser, Value};
use coset::{CoseSign1Builder, HeaderBuilder, TaggedCborSerializable};
use ecdsa::signature::Signer;
use tinyvec::ArrayVec;

use crate::{
    measurement::Measurement,
    rmi::{HASH_ALGO_SHA256, HASH_ALGO_SHA512},
};

use self::claims::RealmClaims;
use crate::rmm_el3::{plat_token, realm_attest_key};

// Arbitrary number.
pub const MAX_CCA_TOKEN_SIZE: usize = 4096;
// This mostly depends on amount of measurement slots used.
// In the maximum it could take around 6kB.
// Currently platform token size is a little over 1kB.
pub const MAX_PLATFORM_TOKEN_SIZE: usize = 2048;
pub const MAX_CHALLENGE_SIZE: usize = 64;

const CCA_TOKEN_COLLECTION: u64 = 399;
const CCA_PLATFORM_TOKEN: u64 = 44234;
const CCA_REALM_DELEGATED_TOKEN: u64 = 44241;

// Hardcoded RAK private key for use in fuzzing, where HES is absent.
#[cfg(fuzzing)]
const RAK_PRIV_KEY: [u8; 48] = [
    60, 140, 180, 183, 23, 21, 46, 76, 243, 33, 155, 38, 242, 82, 86, 0, 57, 97, 140, 67, 71, 234,
    13, 22, 87, 140, 136, 172, 120, 226, 162, 115, 202, 242, 116, 10, 141, 245, 16, 119, 255, 31,
    1, 3, 10, 113, 218, 134,
];

type PlatformToken = ArrayVec<[u8; MAX_PLATFORM_TOKEN_SIZE]>;
// 48B - the length of EC-P384 private key
type RAKPriv = ArrayVec<[u8; 48]>;

#[derive(Debug, Default)]
pub struct Attestation {
    platform_token: PlatformToken,
    rak_priv: RAKPriv,
}

// TODO: Can we keep this context anywhere?
impl Attestation {
    pub fn new(platform_token: &[u8], rak_priv: &[u8]) -> Self {
        let mut at = Self::default();
        at.set_platform_token(platform_token);
        at.set_rak_priv(rak_priv);
        at
    }

    fn set_platform_token(&mut self, token: &[u8]) {
        self.platform_token = token.iter().cloned().collect();
    }

    fn set_rak_priv(&mut self, key_priv: &[u8]) {
        self.rak_priv = key_priv.iter().cloned().collect();
    }

    // TODO: Consider returning errors.
    // Though all errors in here are programmer errors
    // or a result of incorrect data passed from HES.
    pub fn create_attestation_token(
        &self,
        challenge: &[u8],
        measurements: &[Measurement],
        personalization_value: &[u8],
        hash_algo: u8,
    ) -> Vec<u8> {
        let mut cca_token = Vec::new();

        let realm_token =
            self.create_realm_token(challenge, measurements, personalization_value, hash_algo);

        let realm_token_entry = (
            Value::Integer(CCA_REALM_DELEGATED_TOKEN.into()),
            Value::Bytes(realm_token),
        );

        let platform_token_entry = (
            Value::Integer(CCA_PLATFORM_TOKEN.into()),
            Value::Bytes(self.platform_token.to_vec()),
        );

        let token_map: Vec<(Value, Value)> = vec![platform_token_entry, realm_token_entry];

        ser::into_writer(
            &Value::Tag(CCA_TOKEN_COLLECTION, Box::new(Value::Map(token_map))),
            &mut cca_token,
        )
        .expect("Failed to serialize CCA token");

        cca_token
    }

    fn create_realm_token(
        &self,
        challenge: &[u8],
        measurements: &[Measurement],
        personalization_value: &[u8],
        hash_algo: u8,
    ) -> Vec<u8> {
        let hash_algo_id = match hash_algo {
            HASH_ALGO_SHA256 => String::from("sha-256"),
            HASH_ALGO_SHA512 => String::from("sha-512"),
            _ => panic!("Unrecognized hash algorithm {}", hash_algo),
        };

        let secret_key =
            p384::SecretKey::from_slice(&self.rak_priv).expect("Failed to import private RAK.");

        let public_key = secret_key.public_key().to_sec1_bytes().to_vec();

        let claims = RealmClaims::init(
            challenge,
            personalization_value,
            measurements,
            hash_algo_id,
            &public_key,
            // TODO: should this value be stored somewhere else?
            String::from("sha-256"),
        );

        let claims_map: Vec<(Value, Value)> = vec![
            claims.challenge.into(),
            claims.personalization_value.into(),
            claims.rim.into(),
            claims.rems.into(),
            claims.measurement_hash_algo.into(),
            claims.rak_pub.into(),
            claims.rak_pub_hash_algo.into(),
        ];

        let mut realm_token = Vec::new();
        ser::into_writer(&Value::Map(claims_map), &mut realm_token)
            .expect("Failed to serialize realm token");

        let protected = HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::ES384)
            .build();

        let sign1 = CoseSign1Builder::new()
            .protected(protected)
            .payload(realm_token)
            .create_signature(b"", |payload| Self::sign(secret_key, payload))
            .build();

        sign1
            .to_tagged_vec()
            .expect("Failed to create tagged signed token")
    }

    fn sign(secret_key: p384::SecretKey, data: &[u8]) -> Vec<u8> {
        let signing_key = p384::ecdsa::SigningKey::from_bytes(&secret_key.to_bytes())
            .expect("Failed to generate signing key");

        let signature: p384::ecdsa::Signature = signing_key
            .try_sign(data)
            .expect("Failed to create P384 signature");
        signature.to_vec()
    }
}

pub fn get_token(
    challenge: &[u8],
    measurements: &[Measurement],
    personalization_value: &[u8],
    hash_algo: u8,
) -> Vec<u8> {
    // TODO: consider storing attestation object somewhere,
    // as RAK and token do not change during rmm lifetime.
    #[cfg(fuzzing)]
    let realm_attest_key = &RAK_PRIV_KEY;
    #[cfg(not(fuzzing))]
    let realm_attest_key = &realm_attest_key();

    Attestation::new(&plat_token(), realm_attest_key).create_attestation_token(
        challenge,
        measurements,
        personalization_value,
        hash_algo,
    )
}
