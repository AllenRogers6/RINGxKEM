use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce, aead::Aead};
use ed25519_dalek::SigningKey;
use ed25519_dalek::{Signature as Ed25519Signature, Signer, VerifyingKey};
use hkdf::Hkdf;
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::PublicKey as KemPublicKey;
use pqcrypto_traits::kem::{Ciphertext, SharedSecret};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::merkle_tree::{Hash, MerkleTree, verify_proof};
use crate::ring_signature::{RingMember, RingSignature, sign as ring_sign, verify as ring_verify};

pub struct IdentityKey {
    pub secret: kyber768::SecretKey,
    pub public: kyber768::PublicKey,
}

pub struct PreKeyBundle {
    pub pqkem_pub: kyber768::PublicKey,
    pub signature: Vec<u8>,
    pub signer_public: Vec<u8>,
    pub merkle_proof: Vec<Hash>,
}

pub struct RingXKEMSession {
    pub session_key: [u8; 32],
    pub peer_id: String,
}

#[allow(dead_code)]
pub struct PreKeyStore {
    pub bundles: HashMap<String, Vec<PreKeyBundle>>,
    pub ring_members: HashMap<String, Vec<RingMember>>,
}

pub fn generate_identity_keypair() -> (kyber768::PublicKey, kyber768::SecretKey) {
    kyber768::keypair()
}

pub fn create_identity_key(
    public: kyber768::PublicKey,
    secret: kyber768::SecretKey,
) -> IdentityKey {
    IdentityKey { secret, public }
}

#[allow(dead_code)]
impl PreKeyStore {
    pub fn new() -> Self {
        PreKeyStore {
            bundles: HashMap::new(),
            ring_members: HashMap::new(),
        }
    }

    pub fn add_bundle(&mut self, user_id: &str, bundle: PreKeyBundle) {
        self.bundles
            .entry(user_id.to_string())
            .or_default()
            .push(bundle);
    }

    pub fn get_bundle(&self, user_id: &str) -> Option<&PreKeyBundle> {
        self.bundles.get(user_id).and_then(|v| v.first())
    }

    pub fn add_ring_member(&mut self, user_id: &str, member: RingMember) {
        self.ring_members
            .entry(user_id.to_string())
            .or_default()
            .push(member);
    }

    pub fn get_ring(&self, user_id: &str) -> Option<&Vec<RingMember>> {
        self.ring_members.get(user_id)
    }
}

#[allow(dead_code)]
pub fn create_prekey_bundle(
    signer_signing_key: &SigningKey,
    merkle_tree: &MerkleTree,
    prekey_index: usize,
) -> (PreKeyBundle, kyber768::SecretKey) {
    let (pqkem_pub, pqkem_secret) = kyber768::keypair();
    let signature = signer_signing_key
        .sign(pqkem_pub.as_bytes())
        .to_bytes()
        .to_vec();
    let proof = merkle_tree
        .proof(prekey_index)
        .expect("prekey index out of range");
    let bundle = PreKeyBundle {
        pqkem_pub,
        signature,
        signer_public: signer_signing_key.verifying_key().to_bytes().to_vec(),
        merkle_proof: proof,
    };
    (bundle, pqkem_secret)
}

fn flatten_proof(proof: &[Hash]) -> Vec<u8> {
    proof.iter().flatten().copied().collect()
}

pub fn ringxkem_initiate(
    _sender_id: &str,
    _receiver_id: &str,
    receiver_identity_pk: &kyber768::PublicKey,
    bundle: &PreKeyBundle,
    ring: &[RingMember],
    signer_index: usize,
    ring_signer_secret_key: &[u8],
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let (ss_id, ct_id) = kyber768::encapsulate(receiver_identity_pk);
    let (ss_prekey, ct_prekey) = kyber768::encapsulate(&bundle.pqkem_pub);

    let hk = Hkdf::<Sha256>::new(None, &[ss_id.as_bytes(), ss_prekey.as_bytes()].concat());
    let mut session_key = [0u8; 32];
    hk.expand(b"session", &mut session_key).unwrap();

    let mut ring_msg = Vec::new();
    ring_msg.extend_from_slice(ct_id.as_bytes());
    ring_msg.extend_from_slice(ct_prekey.as_bytes());
    ring_msg.extend_from_slice(&bundle.signature);
    ring_msg.extend_from_slice(&bundle.signer_public);
    ring_msg.extend_from_slice(&flatten_proof(&bundle.merkle_proof));

    let ring_signature = ring_sign(&ring_msg, ring, signer_index, ring_signer_secret_key)
        .expect("ring signature generation failed");

    let aead = ChaCha20Poly1305::new(Key::from_slice(&session_key));
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = aead
        .encrypt(nonce, ring_signature.to_bytes().as_ref())
        .expect("encryption failed");

    let mut encrypted_sig = Vec::with_capacity(12 + ciphertext.len());
    encrypted_sig.extend_from_slice(&nonce_bytes);
    encrypted_sig.extend_from_slice(&ciphertext);

    (
        ct_id.as_bytes().to_vec(),
        ct_prekey.as_bytes().to_vec(),
        encrypted_sig,
    )
}

pub fn ringxkem_receive(
    ct_id: &[u8],
    ct_prekey: &[u8],
    encrypted_sig: &[u8],
    identity_sk: &kyber768::SecretKey,
    bundle: &PreKeyBundle,
    prekey_sk: &kyber768::SecretKey,
    ring: &[RingMember],
    prekey_signer_public: &VerifyingKey,
    expected_merkle_root: &Hash,
) -> Result<RingXKEMSession, Box<dyn std::error::Error>> {
    let ct_id_obj = kyber768::Ciphertext::from_bytes(ct_id)?;
    let ct_prekey_obj = kyber768::Ciphertext::from_bytes(ct_prekey)?;
    let ss_id = kyber768::decapsulate(&ct_id_obj, identity_sk);
    let ss_prekey = kyber768::decapsulate(&ct_prekey_obj, prekey_sk);

    let hk = Hkdf::<Sha256>::new(None, &[ss_id.as_bytes(), ss_prekey.as_bytes()].concat());
    let mut session_key = [0u8; 32];
    hk.expand(b"session", &mut session_key).unwrap();

    let sig_bytes: [u8; 64] = bundle
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| "prekey signature must be 64 bytes")?;
    let prekey_sig = Ed25519Signature::from_bytes(&sig_bytes);

    prekey_signer_public.verify_strict(bundle.pqkem_pub.as_bytes(), &prekey_sig)?;

    let mut hasher = Sha256::new();
    hasher.update(pqcrypto_traits::kem::PublicKey::as_bytes(&bundle.pqkem_pub));
    let leaf: Hash = hasher.finalize().into();
    if !verify_proof(&leaf, &bundle.merkle_proof, expected_merkle_root) {
        return Err("Merkle proof verification failed".into());
    }

    if encrypted_sig.len() < 12 {
        return Err("encrypted signature too short".into());
    }
    let (nonce_bytes, ciphertext) = encrypted_sig.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let aead = ChaCha20Poly1305::new(Key::from_slice(&session_key));
    let decrypted_sig_bytes = aead
        .decrypt(nonce, ciphertext)
        .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;

    let ring_signature = RingSignature::from_bytes(&decrypted_sig_bytes)?;

    let mut ring_msg = Vec::new();
    ring_msg.extend_from_slice(ct_id);
    ring_msg.extend_from_slice(ct_prekey);
    ring_msg.extend_from_slice(&bundle.signature);
    ring_msg.extend_from_slice(&bundle.signer_public);
    ring_msg.extend_from_slice(&flatten_proof(&bundle.merkle_proof));

    if !ring_verify(&ring_msg, ring, &ring_signature)? {
        return Err("Ring signature verification failed".into());
    }

    Ok(RingXKEMSession {
        session_key,
        peer_id: "sender".to_string(),
    })
}
