use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};
use std::convert::TryInto;
use std::error::Error;

#[derive(Clone)]
pub struct RingMember {
    pub public_key: Vec<u8>,
    pub secret_key: Option<Vec<u8>>,
}

pub struct RingSignature {
    pub c0: [u8; 32],
    pub s: Vec<[u8; 32]>,
    pub ring_size: usize,
}

impl RingSignature {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 32 + 32 * self.ring_size);
        out.extend_from_slice(&(self.ring_size as u64).to_be_bytes());
        out.extend_from_slice(&self.c0);
        for s in &self.s {
            out.extend_from_slice(s);
        }
        out
    }

    pub fn from_bytes(buf: &[u8]) -> Result<RingSignature, Box<dyn Error>> {
        if buf.len() < 8 + 32 {
            return Err("signature too short".into());
        }
        let ring_size = u64::from_be_bytes(buf[..8].try_into().unwrap()) as usize;
        if buf.len() != 8 + 32 + 32 * ring_size {
            return Err("signature length mismatch".into());
        }
        let c0: [u8; 32] = buf[8..8 + 32].try_into().unwrap();
        let mut s = Vec::with_capacity(ring_size);
        for i in 0..ring_size {
            let start = 8 + 32 + 32 * i;
            let end = start + 32;
            s.push(buf[start..end].try_into().unwrap());
        }
        Ok(RingSignature { c0, s, ring_size })
    }
}

pub fn keygen() -> (Vec<u8>, Vec<u8>) {
    let signing_key = SigningKey::generate(&mut OsRng);
    (
        signing_key.verifying_key().to_bytes().to_vec(),
        signing_key.to_bytes().to_vec(),
    )
}

fn hash_to_scalar(data: &[u8]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(data);
    let digest = hasher.finalize();
    Scalar::from_bytes_mod_order_wide(&digest.into())
}

fn challenge(message: &[u8], r: &[u8; 32], public_key: &[u8]) -> Scalar {
    let mut data = Vec::with_capacity(message.len() + 32 + public_key.len());
    data.extend_from_slice(message);
    data.extend_from_slice(r);
    data.extend_from_slice(public_key);
    hash_to_scalar(&data)
}

fn secret_scalar_from_seed(seed: &[u8]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(seed);
    let digest = hasher.finalize();
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&digest[..32]);
    scalar_bytes[0] &= 248;
    scalar_bytes[31] &= 127;
    scalar_bytes[31] |= 64;
    Scalar::from_bytes_mod_order(scalar_bytes)
}

pub fn sign(
    message: &[u8],
    ring: &[RingMember],
    signer_index: usize,
    secret_key_seed: &[u8],
) -> Result<RingSignature, Box<dyn Error>> {
    let n = ring.len();
    if signer_index >= n {
        return Err("invalid signer index".into());
    }
    if secret_key_seed.len() != 32 {
        return Err("secret key seed must be 32 bytes".into());
    }

    let mut pubkeys = Vec::with_capacity(n);
    for member in ring {
        let pk_bytes: [u8; 32] = member
            .public_key
            .as_slice()
            .try_into()
            .map_err(|_| "public key must be 32 bytes")?;
        let point = CompressedEdwardsY(pk_bytes)
            .decompress()
            .ok_or("invalid public key point")?;
        pubkeys.push(point);
    }

    let mut rng = OsRng;

    let u = Scalar::random(&mut rng);
    let r_s = (ED25519_BASEPOINT_POINT * u).compress().to_bytes();

    let mut c_next = challenge(message, &r_s, &ring[signer_index].public_key);

    let mut s_responses = vec![[0u8; 32]; n];

    let mut i = (signer_index + 1) % n;
    while i != signer_index {
        let z_i = Scalar::random(&mut rng);
        let r_i = (ED25519_BASEPOINT_POINT * z_i - pubkeys[i] * c_next)
            .compress()
            .to_bytes();
        s_responses[i] = z_i.to_bytes();
        c_next = challenge(message, &r_i, &ring[i].public_key);
        i = (i + 1) % n;
    }

    let c_s = c_next;

    let a_s = secret_scalar_from_seed(secret_key_seed);
    let z_s = u + c_s * a_s;
    s_responses[signer_index] = z_s.to_bytes();

    let mut challenges = vec![Scalar::from_bytes_mod_order([0u8; 32]); n];
    challenges[signer_index] = c_s;

    let mut idx = (signer_index + 1) % n;
    while idx != signer_index {
        let prev = (idx + n - 1) % n;
        let z_prev = Scalar::from_bytes_mod_order(s_responses[prev]);
        let c_prev = challenges[prev];
        let r_prev = (ED25519_BASEPOINT_POINT * z_prev - pubkeys[prev] * c_prev)
            .compress()
            .to_bytes();
        challenges[idx] = challenge(message, &r_prev, &ring[prev].public_key);
        idx = (idx + 1) % n;
    }

    let c0 = challenges[0];

    Ok(RingSignature {
        c0: c0.to_bytes(),
        s: s_responses,
        ring_size: n,
    })
}

pub fn verify(
    message: &[u8],
    ring: &[RingMember],
    signature: &RingSignature,
) -> Result<bool, Box<dyn Error>> {
    let n = ring.len();
    if signature.ring_size != n || signature.s.len() != n {
        return Ok(false);
    }

    let mut pubkeys = Vec::with_capacity(n);
    for member in ring {
        let pk_bytes: [u8; 32] = member
            .public_key
            .as_slice()
            .try_into()
            .map_err(|_| "public key must be 32 bytes")?;
        let point = CompressedEdwardsY(pk_bytes)
            .decompress()
            .ok_or("invalid public key point")?;
        pubkeys.push(point);
    }

    let mut c_current = Scalar::from_bytes_mod_order(signature.c0);

    for i in 0..n {
        let z_i = Scalar::from_bytes_mod_order(signature.s[i]);
        let r_i = (ED25519_BASEPOINT_POINT * z_i - pubkeys[i] * c_current)
            .compress()
            .to_bytes();
        c_current = challenge(message, &r_i, &ring[i].public_key);
    }

    Ok(c_current.to_bytes() == signature.c0)
}
