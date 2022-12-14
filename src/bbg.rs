//! Implementation of Hierarchical Identity Based Encryption (HIBE)
//!
//! This implementation has a ciphertext length of 3 group elements (one from each pairing domain
//! and one from the codomain), and thus has shorter (and constant-sized) ciphertexts when compared
//! to the original suggestion by Canetti, Halevi and Katz.
//!
//! This implementation is taken from *Hierarchical Identity Based Encryption with Constant Size
//! Ciphertext* by Dan Boneh, Xavier Boyen and Eu-Jin Goh.
use arrayvec::ArrayVec;
use bls12_381::{pairing, G1Affine, G2Affine, G2Projective, Gt, Scalar};
use ff::Field;
use group::Group;
use rand::Rng;
use sha3::{Digest, Sha3_256};

use super::NodeName;

const DEPTH: usize = 32;
/* Y	1	[a1, b, g, g1]
 * Y	2	[a0, c, g2, g3, h]
 */
pub type PublicParams = (G1Affine, G1Affine, G2Affine, G2Affine, ArrayVec<G2Affine, DEPTH>);
pub type MasterKey = G2Affine;
pub type PrivateKey = (G2Affine, G1Affine, ArrayVec<G2Affine, DEPTH>);
pub type Message = Gt;
pub type Ciphertext = (Gt, G1Affine, G2Affine);

fn nodename_to_identity(name: NodeName) -> Vec<Scalar> {
    let mut result = Vec::new();
    let path = name.path();
    for i in 1..=name.len() {
        let mut hasher = Sha3_256::new();
        hasher.update(&[i]);
        let current = (path >> (name.len() - i)) & 1;
        hasher.update(&[current as u8]);

        let output: [u8; 32] = hasher.finalize().into();
        let raw: [u64; 4] = output
            .chunks(8)
            .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
            .collect::<ArrayVec<_, 4>>()
            .into_inner()
            .unwrap();
        let scalar = Scalar::from_raw(raw);
        result.push(scalar);
    }
    result
}

pub fn setup<R: Rng>(mut rng: R) -> (PublicParams, MasterKey) {
    let g = G1Affine::generator();
    let alpha = Scalar::random(&mut rng);
    let g1 = g * alpha;
    let g2 = G2Projective::random(&mut rng);
    let g3 = G2Projective::random(&mut rng);
    let hs = (0..DEPTH)
        .map(|_| G2Projective::random(&mut rng))
        .map(Into::into)
        .collect();
    (
        (g, g1.into(), g2.into(), g3.into(), hs),
        (g2 * alpha).into(),
    )
}

pub fn keygen<R: Rng>(
    rng: R,
    public_params: &PublicParams,
    master_key: &MasterKey,
    name: NodeName,
) -> PrivateKey {
    let id = nodename_to_identity(name);
    let r = Scalar::random(rng);
    (
        (master_key
            + (public_params
                .4
                .iter()
                .zip(id)
                .map(|(h, i)| h * i)
                .sum::<G2Projective>()
                + public_params.3)
                * r)
            .into(),
        (public_params.0 * r).into(),
        public_params.4[name.len() as usize..]
            .iter()
            .map(|h| (h * r).into())
            .collect(),
    )
}

pub fn derive<R: Rng>(
    rng: R,
    public_params: &PublicParams,
    parent_key: &PrivateKey,
    parent_name: NodeName,
    name: NodeName,
) -> PrivateKey {
    assert_eq!(name.parent(), parent_name);
    let id = nodename_to_identity(name);
    let t = Scalar::random(rng);
    (
        (parent_key.0
            + parent_key.2[0] * id.last().unwrap()
            + (public_params
                .4
                .iter()
                .zip(id)
                .map(|(h, i)| h * i)
                .sum::<G2Projective>()
                + public_params.3)
                * t)
            .into(),
        (parent_key.1 + public_params.0 * t).into(),
        parent_key.2[1..]
            .iter()
            .zip(public_params.4[name.len() as usize..].iter())
            .map(|(b, h)| b + h * t)
            .map(Into::into)
            .collect(),
    )
}

pub fn encrypt<R: Rng>(
    rng: R,
    public_params: &PublicParams,
    name: NodeName,
    message: &Message,
) -> Ciphertext {
    let id = nodename_to_identity(name);
    let s = Scalar::random(rng);
    (
        pairing(&public_params.1, &public_params.2) * s + message,
        (public_params.0 * s).into(),
        ((public_params
            .4
            .iter()
            .zip(id.iter())
            .map(|(h, i)| h * i)
            .sum::<G2Projective>()
            + public_params.3)
            * s)
            .into(),
    )
}

pub fn decrypt(public_params: &PublicParams, key: &PrivateKey, ciphertext: &Ciphertext) -> Message {
    let (a, b, c) = ciphertext;
    a + pairing(&key.1, c) - pairing(b, &key.0)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn roundtrip_root() {
        let mut rng = rand::thread_rng();
        let message = Gt::random(&mut rng);

        let (params, master) = setup(&mut rng);
        let sk = keygen(&mut rng, &params, &master, NodeName::ROOT);
        let cipher = encrypt(&mut rng, &params, NodeName::ROOT, &message);
        let plain = decrypt(&params, &sk, &cipher);

        assert_eq!(plain, message);
    }

    #[test]
    fn roundtrip_derived() {
        let mut rng = rand::thread_rng();
        let message = Gt::random(&mut rng);

        let (params, master) = setup(&mut rng);
        let sk = keygen(&mut rng, &params, &master, NodeName::ROOT);
        let sk = derive(&mut rng, &params, &sk, NodeName::ROOT, NodeName::ROOT.left());
        let sk = derive(&mut rng, &params, &sk, NodeName::ROOT.left(), NodeName::ROOT.left().left());
        let sk = derive(&mut rng, &params, &sk, NodeName::ROOT.left().left(), NodeName::ROOT.left().left().right());

        let cipher = encrypt(&mut rng, &params, NodeName::ROOT.left().left().right(), &message);
        let plain = decrypt(&params, &sk, &cipher);

        assert_eq!(plain, message);
    }
}
