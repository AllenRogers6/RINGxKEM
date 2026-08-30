use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

pub struct MerkleTree {
    levels: Vec<Vec<Hash>>,
}

impl MerkleTree {
    pub fn new(leaf_hashes: &[Hash]) -> Option<Self> {
        if leaf_hashes.is_empty() {
            return None;
        }

        let mut levels = Vec::new();
        levels.push(leaf_hashes.to_vec());

        while levels.last().unwrap().len() > 1 {
            let current = levels.last().unwrap();
            let mut next_level = Vec::with_capacity((current.len() + 1) / 2);

            for pair in current.chunks(2) {
                let left = pair[0];
                let right = if pair.len() == 2 { pair[1] } else { pair[0] };
                let parent = hash_pair(&left, &right);
                next_level.push(parent);
            }
            levels.push(next_level);
        }

        Some(MerkleTree { levels })
    }

    pub fn root(&self) -> Hash {
        *self.levels.last().unwrap().first().unwrap()
    }

    pub fn proof(&self, index: usize) -> Option<Vec<Hash>> {
        if index >= self.levels[0].len() {
            return None;
        }

        let mut proof = Vec::new();
        let mut idx = index;
        for level in &self.levels[..self.levels.len() - 1] {
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            let sibling = if sibling_idx < level.len() {
                level[sibling_idx]
            } else {
                level[level.len() - 1]
            };
            proof.push(sibling);
            idx /= 2;
        }
        Some(proof)
    }
}

fn hash_pair(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    let digest: [u8; 32] = hasher.finalize().into();
    digest
}

pub fn verify_proof(leaf: &Hash, proof: &[Hash], root: &Hash) -> bool {
    let mut current = *leaf;
    for sibling in proof {
        current = hash_pair(&current, sibling);
    }
    &current == root
}
