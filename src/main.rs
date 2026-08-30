mod merkle_tree;
mod ring_signature;
mod ringxkem;

use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;
use merkle_tree::{Hash, MerkleTree};
use pqcrypto_traits::kem::PublicKey;
use ring_signature::{RingMember, keygen as ring_keygen};
use ringxkem::*;
use sha2::{Digest, Sha256};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("RINGxKEM demo");

    let (receiver_kyber_pub, receiver_kyber_sk) = generate_identity_keypair();
    let receiver_identity = create_identity_key(receiver_kyber_pub, receiver_kyber_sk);

    let receiver_ed25519_signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let receiver_ed25519_verifying_key = receiver_ed25519_signing_key.verifying_key();

    const NUM_PREKEYS: usize = 4;
    let mut prekey_hashes: Vec<Hash> = Vec::new();
    let mut prekey_keypairs = Vec::new();

    for _ in 0..NUM_PREKEYS {
        let (pqkem_pub, pqkem_sk) = pqcrypto_kyber::kyber768::keypair();
        let mut h = Sha256::new();
        h.update(pqkem_pub.as_bytes());
        let leaf: Hash = h.finalize().into();
        prekey_hashes.push(leaf);
        prekey_keypairs.push((pqkem_pub, pqkem_sk));
    }

    let merkle_tree = MerkleTree::new(&prekey_hashes).expect("non-empty");
    let merkle_root = merkle_tree.root();

    let mut prekey_bundles = Vec::new();
    for i in 0..NUM_PREKEYS {
        let (pqkem_pub, pqkem_sk) = prekey_keypairs.remove(0);
        let signature = receiver_ed25519_signing_key
            .sign(pqkem_pub.as_bytes())
            .to_bytes()
            .to_vec();
        let proof = merkle_tree.proof(i).unwrap();
        let bundle = PreKeyBundle {
            pqkem_pub,
            signature,
            signer_public: receiver_ed25519_verifying_key.to_bytes().to_vec(),
            merkle_proof: proof,
        };
        prekey_bundles.push((bundle, pqkem_sk));
    }

    let (bundle, prekey_sk) = prekey_bundles.remove(0);

    // 3 member ring
    let mut ring_members = Vec::new();
    for i in 0..3 {
        let (pk, sk) = ring_keygen();
        let member = RingMember {
            public_key: pk,
            secret_key: if i == 0 { Some(sk) } else { None },
        };
        ring_members.push(member);
    }

    let (ct_id, ct_prekey, encrypted_sig) = ringxkem_initiate(
        "sender",
        "receiver",
        &receiver_identity.public,
        &bundle,
        &ring_members,
        0,
        &ring_members[0].secret_key.as_ref().unwrap(),
    );

    println!("Ciphertext ID length: {}", ct_id.len());
    println!("Ciphertext Prekey length: {}", ct_prekey.len());
    println!("Encrypted signature length: {}", encrypted_sig.len());

    let session = ringxkem_receive(
        &ct_id,
        &ct_prekey,
        &encrypted_sig,
        &receiver_identity.secret,
        &bundle,
        &prekey_sk,
        &ring_members,
        &receiver_ed25519_verifying_key,
        &merkle_root,
    )?;

    println!("\nSession established successfully!");
    println!("Session key: {:?}", session.session_key);
    println!("Peer ID: {}\n", session.peer_id);

    println!("Testing with wrong ring");
    let wrong_ring = vec![
        RingMember {
            public_key: vec![0u8; 32],
            secret_key: None,
        },
        RingMember {
            public_key: vec![1u8; 32],
            secret_key: None,
        },
        RingMember {
            public_key: vec![2u8; 32],
            secret_key: None,
        },
    ];
    let wrong_result = ringxkem_receive(
        &ct_id,
        &ct_prekey,
        &encrypted_sig,
        &receiver_identity.secret,
        &bundle,
        &prekey_sk,
        &wrong_ring,
        &receiver_ed25519_verifying_key,
        &merkle_root,
    );
    println!(
        "Verification with wrong ring should fail: {}",
        wrong_result.is_err()
    );

    Ok(())
}
