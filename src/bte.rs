//! This submodule implements the "binary tree encryption" from Canetti et al.'s paper.
//!
//! The "tree depth" (t) is limited to 32. Note that all functions that take randomness (`R: Rng`)
//! should be called with cryptographically secure random generators! For the ease of use and
//! testing, this is not restricted in those functions, as they should be seen as lower-level
//! implementation details. On the high level, consider restricting `R: Rng + CryptoRng`.

use arrayvec::ArrayVec;
use bls12_381::{pairing, G1Affine, G2Affine, Gt, Scalar};
use ff::Field;
use rand::Rng;
use sha3::{Digest, Sha3_256};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::NodeName;

pub type PK = G1Affine;
pub type SK = (ArrayVec<G1Affine, 32>, G2Affine);

pub type Message = Gt;
pub type Ciphertext = (G1Affine, ArrayVec<G2Affine, 32>, Gt);

/// Implementation of the hash function.
///
/// Note that we are working in the random oracle model here, as we simply use a cryptographically
/// secure hash function instead of the "t-wise independent" hash.
fn hash_to_g2(name: NodeName) -> G2Affine {
    let mut hasher = Sha3_256::new();
    hasher.update(&[name.len()]);
    hasher.update(name.path().to_le_bytes());

    let output: [u8; 32] = hasher.finalize().into();
    let raw: [u64; 4] = output
        .chunks(8)
        .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
        .collect::<ArrayVec<_, 4>>()
        .into_inner()
        .unwrap();
    let scalar = Scalar::from_raw(raw);
    (G2Affine::generator() * scalar).into()
}

/// The key generation algorithm returns a public key and an initial (root) secret key.
pub fn gen<R: Rng>(r: R) -> (PK, SK) {
    let alpha = Scalar::random(r);
    let pk = (G1Affine::generator() * alpha).into();
    let sk = (
        Default::default(),
        (hash_to_g2(NodeName::ROOT) * alpha).into(),
    );
    (pk, sk)
}

/// The key derivation algorithm takes the name and secret key of a node and returns the two secret
/// keys of the children.
pub fn der<R: Rng>(mut rng: R, name: NodeName, key: &SK) -> (SK, SK) {
    let mut left = key.clone();
    let randomness = Scalar::random(&mut rng);
    let extension = (G1Affine::generator() * randomness).into();
    left.0.push(extension);
    left.1 = (left.1 + hash_to_g2(name.left()) * randomness).into();

    let mut right = key.clone();
    let randomness = Scalar::random(&mut rng);
    let extension = (G1Affine::generator() * randomness).into();
    right.0.push(extension);
    right.1 = (right.1 + hash_to_g2(name.right()) * randomness).into();

    (left, right)
}

/// The encryption algorithm takes the public key, the name of a node, and a message, and it
/// returns the ciphertext.
pub fn enc<R: Rng>(rng: R, key: &PK, name: NodeName, message: Message) -> Ciphertext {
    let gamma = Scalar::random(rng);
    let d = pairing(key, &hash_to_g2(NodeName::ROOT)) * gamma;
    (
        (G1Affine::generator() * gamma).into(),
        name.walk()
            .map(|p| hash_to_g2(p) * gamma)
            .map(Into::into)
            .collect(),
        message + d,
    )
}

/// The decryption algorithm takes the public key, the name of a node, its secret key, and a
/// ciphertext, and it returns the decrypted message.
pub fn dec(public_key: &PK, name: NodeName, secret_key: &SK, ciphertext: &Ciphertext) -> Message {
    let denominator: Gt = secret_key
        .0
        .iter()
        .zip(ciphertext.1.iter())
        .map(|(rs, us)| pairing(rs, us))
        .sum();
    let numerator = pairing(&ciphertext.0, &secret_key.1);
    ciphertext.2 - (numerator - denominator)
}

#[cfg(test)]
mod test {
    use super::*;
    use group::Group;

    #[test]
    fn left_child() {
        assert_eq!(NodeName::ROOT.left(), NodeName::new(1, 0));
    }

    #[test]
    fn right_child() {
        assert_eq!(NodeName::ROOT.right(), NodeName::new(1, 1));
    }

    #[test]
    fn walk() {
        let node = NodeName::ROOT.left().right().right();
        let walk = node.walk().collect::<Vec<_>>();
        assert_eq!(
            walk,
            vec![
                NodeName::ROOT.left(),
                NodeName::ROOT.left().right(),
                NodeName::ROOT.left().right().right()
            ]
        );
    }

    #[test]
    fn roundtrip_root() {
        let mut rng = rand::thread_rng();
        let message = Gt::random(&mut rng);

        let (pk, sk) = gen(&mut rng);
        let cipher = enc(&mut rng, &pk, NodeName::ROOT, message);
        let plain = dec(&pk, NodeName::ROOT, &sk, &cipher);

        assert_eq!(plain, message);
    }

    #[test]
    fn roundtrip_child() {
        let mut rng = rand::thread_rng();
        let message = Gt::random(&mut rng);

        let node = NodeName::ROOT.left().left().right();

        let (pk, sk) = gen(&mut rng);
        let (sk, _) = der(&mut rng, NodeName::ROOT, &sk);
        let (sk, _) = der(&mut rng, NodeName::ROOT.left(), &sk);
        let (_, sk) = der(&mut rng, NodeName::ROOT.left().left(), &sk);
        let cipher = enc(&mut rng, &pk, node, message);
        let plain = dec(&pk, node, &sk, &cipher);

        assert_eq!(plain, message);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serialize() {
        let mut rng = rand::thread_rng();
        let message = Gt::random(&mut rng);

        let (pk, sk) = gen(&mut rng);
        let cipher = enc(&mut rng, &pk, NodeName::ROOT, message);
        let serialized = bincode::serialize(&cipher).unwrap();
        let deserialized = bincode::deserialize(&serialized).unwrap();
        assert_eq!(cipher, deserialized);
    }
}
