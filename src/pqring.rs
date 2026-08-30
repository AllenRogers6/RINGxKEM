use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
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
        let mut out = Vec::new();
        out.extend_from_slice(&(self.ring_size as u64).to_be_bytes());
        out.extend_from_slice(&self.c0);
        for s in &self.s {
            out.extend_from_slice(s);
        }
        out
    }

    pub fn from_bytes(buf: &[u8]) -> Result<RingSignature, Box<dyn Error>> {
        let mut idx = 0;
        let len = buf.len();
        fn require(idx: usize, need: usize, len: usize) -> Result<(), Box<dyn Error>> {
            if idx + need > len {
                return Err("unexpected end of input".into());
            }
            Ok(())
        }

        require(idx, 8, len)?;
        let ring_size = u64::from_be_bytes(buf[idx..idx + 8].try_into().unwrap()) as usize;
        idx += 8;

        require(idx, 32, len)?;
        let c0: [u8; 32] = buf[idx..idx + 32].try_into().unwrap();
        idx += 32;

        let mut s = Vec::with_capacity(ring_size);
        for _ in 0..ring_size {
            require(idx, 32, len)?;
            let si: [u8; 32] = buf[idx..idx + 32].try_into().unwrap();
            idx += 32;
            s.push(si);
        }

        if idx != len {
            return Err("trailing bytes".into());
        }

        Ok(RingSignature { c0, s, ring_size })
    }
}

pub fn keygen() -> (Vec<u8>, Vec<u8>) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (
        verifying_key.to_bytes().to_vec(),
        signing_key.to_bytes().to_vec(),
    )
}

fn hash_to_scalar(data: &[u8]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(data);
    let digest = hasher.finalize();
    Scalar::from_bytes_mod_order_wide(&digest.into())
}

fn challenge(m: &[u8], r: &[u8; 32], pubkey: &[u8]) -> Scalar {
    let mut data = Vec::new();
    data.extend_from_slice(m);
    data.extend_from_slice(r);
    data.extend_from_slice(pubkey);
    hash_to_scalar(&data)
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

    let signing_key = SigningKey::from_bytes(secret_key_seed.try_into().unwrap());
    let our_pubkey = signing_key.verifying_key().to_bytes();

    let mut pubkeys_points = Vec::with_capacity(n);
    for member in ring {
        let pk_bytes: [u8; 32] = member.public_key.as_slice().try_into()?;
        let point = curve25519_dalek::edwards::CompressedEdwardsY(pk_bytes)
            .decompress()
            .ok_or("invalid public key point")?;
        pubkeys_points.push(point);
    }

    let mut rng = OsRng;

    let u = Scalar::random(&mut rng);
    let r_s = (ED25519_BASEPOINT_POINT * u).compress().to_bytes();

    let mut c_next = challenge(message, &r_s, &our_pubkey);

    let mut s_responses = vec![[0u8; 32]; n];

    let mut i = (signer_index + 1) % n;
    while i != signer_index {
        let z_i = Scalar::random(&mut rng);
        let r_i = (ED25519_BASEPOINT_POINT * z_i - pubkeys_points[i] * c_next)
            .compress()
            .to_bytes();
        s_responses[i] = z_i.to_bytes();
        c_next = challenge(message, &r_i, &ring[i].public_key);
        i = (i + 1) % n;
    }

    let c_s = c_next;

    let mut h = Sha512::new();
    h.update(secret_key_seed);
    let digest = h.finalize();
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&digest[..32]);
    scalar_bytes[0] &= 248;
    scalar_bytes[31] &= 127;
    scalar_bytes[31] |= 64;
    let a_s = Scalar::from_bytes_mod_order(scalar_bytes);

    let z_s = u + c_s * a_s;
    s_responses[signer_index] = z_s.to_bytes();

    let mut challenges = vec![Scalar::from_bytes_mod_order([0u8; 32]); n];
    challenges[signer_index] = c_s;
    let mut idx = (signer_index + 1) % n;
    while idx != signer_index {
        let prev = (idx + n - 1) % n;
        let z_prev = Scalar::from_bytes_mod_order(s_responses[prev]);
        let c_prev_val = challenges[prev];
        let pub_prev = pubkeys_points[prev];
        let r_prev = (ED25519_BASEPOINT_POINT * z_prev - pub_prev * c_prev_val)
            .compress()
            .to_bytes();
        let c_new = challenge(message, &r_prev, &ring[prev].public_key);
        challenges[idx] = c_new;
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

    let mut pubkeys_points = Vec::with_capacity(n);
    for member in ring {
        let pk_bytes: [u8; 32] = member.public_key.as_slice().try_into()?;
        let point = curve25519_dalek::edwards::CompressedEdwardsY(pk_bytes)
            .decompress()
            .ok_or("invalid public key point")?;
        pubkeys_points.push(point);
    }

    let mut c_current = Scalar::from_bytes_mod_order(signature.c0);

    for i in 0..n {
        let z_i = Scalar::from_bytes_mod_order(signature.s[i]);
        let r_i = (ED25519_BASEPOINT_POINT * z_i - pubkeys_points[i] * c_current)
            .compress()
            .to_bytes();
        c_current = challenge(message, &r_i, &ring[i].public_key);
    }

    Ok(c_current.to_bytes() == signature.c0)
}
