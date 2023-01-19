//! This crate implemens *Forward-Secure Public-Key Encryption*.
//!
//! The algorithm is based on the paper "A Forward-Secure Public-Key Encryption Scheme" by Ran
//! Canetti, Shai Halevi and Jonathan Katz.
//!
//! The underlying elliptic curve and pairing is the [BLS12-381
//! curve](https://crates.io/crates/bls12_381).
//!
//! **Warning**: This crate is part of academic research and no guarantees about its actual
//! security in practice are made. Use it at your own risk!
//!
//! # Forward Secrecy
//!
//! Intuitively, forward secrecy means that when a key is compromised, the attacker does not gain
//! the ability to read *past* messages that were encrypted before the key compromise. This usually
//! entails some sort of *key evolution* mechanism that generates new key material, such that old
//! keys cannot be constructed from the new keys.
//!
//! # Encryption
//!
//! Note that encrypting points on a elliptic curve is not so useful for practical applications, as
//! messages are usually bytestrings (`&[u8]`) and not elements on the curve. There are ways to map
//! byte strings to curve points, but that severly limits the range of possible input values.
//!
//! Instead, we build a hybrid encryption system on top, such that we choose a random group element
//! as base, derive a key using a secure hash, encrypt the payload using a symmetric cipher (AES)
//! and then send the encrypted group element and the encrypted payload.
//!
//! # Padding
//!
//! Note that this implementation does not apply padding to the input payload! It is the duty of
//! the callers to ensure that the payload length does not leak information.
use aes::cipher::{KeyIvInit, StreamCipher};
use bls12_381::Gt;
use group::Group;
use rand::{CryptoRng, Rng};
use sha3::Digest;
use thiserror::Error;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

mod bbg;
#[allow(unused_variables, dead_code)]
mod bte;
#[cfg(feature = "serde")]
pub mod keyprivate;
mod nodename;

pub use nodename::NodeName;

type Aes128Ctr64LE = ctr::Ctr64LE<aes::Aes128>;
static IV: [u8; 16] = [0; 16];

#[derive(Error, Debug)]
pub enum RatchetError {
    #[error("the ratchet is exhausted and has no more keys")]
    Exhausted,
}

/// Ciphertext representation
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug)]
pub struct Ciphertext {
    hidden_key: bbg::PreDiffieKey,
    payload: Vec<u8>,
}

/// Structure representing a ratchetable public key.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    inner_key: bbg::PublicParams,
    current_name: NodeName,
}

impl PublicKey {
    /// Ratchet the current key forward.
    ///
    /// Note that private key and public key must be ratcheted "in sync", otherwise messages
    /// encrypted with the (older or newer) public key cannot be decrypted.
    ///
    /// **Note**: The "public key ratcheting" is reversible, that is you can go from a newer public
    /// key to an old one. Since public keys are assumed to be public information, this is not seen
    /// as a security problem.
    pub fn ratchet(&mut self) -> Result<(), RatchetError> {
        self.current_name = self.current_name.next().ok_or(RatchetError::Exhausted)?;
        Ok(())
    }

    /// Encrypt the given payload.
    pub fn encrypt<R: Rng + CryptoRng>(
        &self,
        mut rng: R,
        mut payload: Vec<u8>,
    ) -> Result<Ciphertext, RatchetError> {
        let (key, hidden_key) = bbg::pre_diffie_hellman(&mut rng, &self.inner_key, self.current_name);
        let aes_key = kdf(&key);
        let mut cipher = Aes128Ctr64LE::new(&aes_key.into(), &IV.into());
        cipher.apply_keystream(&mut payload);

        Ok(Ciphertext {
            hidden_key,
            payload,
        })
    }

    /// Checks whether the given ciphertext has been created with the public key.
    pub fn affiliated(&self, ciphertext: &Ciphertext) -> bool {
        bbg::link_diffie(&self.inner_key, &ciphertext.hidden_key, self.current_name)
    }
}

/// Structure representing a ratchetable private key.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateKey {
    public_params: bbg::PublicParams,
    keystack: Vec<bbg::PrivateKey>,
    current_name: NodeName,
}

impl PrivateKey {
    /// Ratchet the current key forward.
    ///
    /// Note that private key and public key must be ratcheted "in sync", otherwise messages
    /// encrypted with the (older or newer) public key cannot be decrypted.
    ///
    /// This is an irreversible operation, you cannot "ratchet backwards". In this way, forward
    /// secrecy is ensured.
    ///
    /// **Note**: This is a proof-of-concept implementation. There is no guarantee that the backing
    /// memory will actually be erased securely.
    pub fn ratchet<R: Rng + CryptoRng>(&mut self, mut rng: R) -> Result<(), RatchetError> {
        let next_name = self.current_name.next().ok_or(RatchetError::Exhausted)?;
        let current_key = self.keystack.pop().unwrap();
        if !self.current_name.is_leaf() {
            let left = bbg::derive(
                &mut rng,
                &self.public_params,
                &current_key,
                self.current_name,
                self.current_name.left(),
            );
            let right = bbg::derive(
                &mut rng,
                &self.public_params,
                &current_key,
                self.current_name,
                self.current_name.right(),
            );
            self.keystack.push(right);
            self.keystack.push(left);
        }
        self.current_name = next_name;
        Ok(())
    }

    pub fn decrypt(&self, mut ciphertext: Ciphertext) -> Result<Vec<u8>, RatchetError> {
        let key = bbg::post_diffie_hellman(self.keystack.last().unwrap(), &ciphertext.hidden_key);
        let aes_key = kdf(&key);
        let mut cipher = Aes128Ctr64LE::new(&aes_key.into(), &IV.into());
        cipher.apply_keystream(&mut ciphertext.payload);

        Ok(ciphertext.payload)
    }
}

/// Generates a new key pair "at the origin".
///
/// This returns a key pair where each key is in epoch 0.
pub fn generate_keypair<R: Rng + CryptoRng>(rng: R) -> (PublicKey, PrivateKey) {
    generate_keypair_in_epoch(rng, 0)
}

/// Generates a new key pair.
///
/// Both keys are fast-forwarded to be in the given epoch. Note that fast forwarding is only
/// possible during the key generation, as we will lose the master key afterwards (otherwise
/// forward secrecy would be broken).
pub fn generate_keypair_in_epoch<R: Rng + CryptoRng>(
    mut rng: R,
    epoch: u64,
) -> (PublicKey, PrivateKey) {
    let (public_params, master_key) = bbg::setup(&mut rng);
    let current_name = NodeName::from_numbering(epoch);
    let mut keystack = Vec::new();
    keystack.extend(current_name.walk().filter_map(|name| {
        if name == name.parent().left() {
            Some(bbg::keygen(
                &mut rng,
                &public_params,
                &master_key,
                name.parent().right(),
            ))
        } else {
            None
        }
    }));
    keystack.push(bbg::keygen(
        &mut rng,
        &public_params,
        &master_key,
        current_name,
    ));
    let public = PublicKey {
        inner_key: public_params.clone(),
        current_name,
    };
    let private = PrivateKey {
        public_params,
        keystack,
        current_name,
    };
    (public, private)
}

fn kdf(group_element: &Gt) -> [u8; 16] {
    let mut hasher = sha3::Sha3_256::new();
    for octabyte in group_element.content() {
        hasher.update(octabyte.to_le_bytes());
    }
    let result: [u8; 32] = hasher.finalize().into();
    result[..16].try_into().unwrap()
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn keypair_generation() {
        generate_keypair(rand::thread_rng());
    }

    #[test]
    fn public_key_ratchet() {
        let (mut pk, _) = generate_keypair(rand::thread_rng());
        pk.ratchet().unwrap();
        assert_eq!(pk.current_name, NodeName::new(1, 0));
        for _ in 0..32 {
            pk.ratchet().unwrap();
        }
        assert_eq!(pk.current_name, NodeName::new(32, 1));
    }

    #[test]
    fn private_key_ratchet() {
        let mut rng = rand::thread_rng();
        let (_, mut sk) = generate_keypair(&mut rng);
        sk.ratchet(&mut rng).unwrap();
        assert_eq!(sk.current_name, NodeName::new(1, 0));
        for _ in 0..32 {
            sk.ratchet(&mut rng).unwrap();
        }
        assert_eq!(sk.current_name, NodeName::new(32, 1));
    }

    #[test]
    fn message_roundtrip() {
        let message: &[u8] = b"Hello, world!";

        let mut rng = rand::thread_rng();
        let (mut pk, mut sk) = generate_keypair(&mut rng);

        let cipher = pk.encrypt(&mut rng, message.into()).unwrap();
        let plain = sk.decrypt(cipher).unwrap();
        assert_eq!(plain, message);

        pk.ratchet().unwrap();
        sk.ratchet(&mut rng).unwrap();

        let cipher = pk.encrypt(&mut rng, message.into()).unwrap();
        let plain = sk.decrypt(cipher).unwrap();
        assert_eq!(plain, message);
    }

    #[test]
    fn message_roundtrip_epoch() {
        let message: &[u8] = b"Hello, world!";

        let mut rng = rand::thread_rng();
        let (mut pk, mut sk) = generate_keypair_in_epoch(&mut rng, 2u64.pow(32) + 42);

        let cipher = pk.encrypt(&mut rng, message.into()).unwrap();
        let plain = sk.decrypt(cipher).unwrap();
        assert_eq!(plain, message);

        pk.ratchet().unwrap();
        sk.ratchet(&mut rng).unwrap();

        let cipher = pk.encrypt(&mut rng, message.into()).unwrap();
        let plain = sk.decrypt(cipher).unwrap();
        assert_eq!(plain, message);
    }

    #[test]
    fn message_roundtrip_through_epochs() {
        let message: &[u8] = b"Hello, world!";
        let mut rng = ChaCha8Rng::from_seed([0; 32]);

        let (mut pk, _) = generate_keypair(rng.clone());
        let (_, sk) = generate_keypair_in_epoch(rng.clone(), 42);

        for _ in 0..42 {
            pk.ratchet().unwrap();
        }

        let cipher = pk.encrypt(&mut rng, message.into()).unwrap();
        let plain = sk.decrypt(cipher).unwrap();
        assert_eq!(plain, message);
    }

    #[test]
    fn secret_key_too_advanced() {
        let message: &[u8] = b"Hello, world!";

        let mut rng = rand::thread_rng();
        let (pk, mut sk) = generate_keypair(&mut rng);

        sk.ratchet(&mut rng).unwrap();

        let cipher = pk.encrypt(&mut rng, message.into()).unwrap();
        let plain = sk.decrypt(cipher).unwrap();
        assert_ne!(plain, message);
    }

    #[test]
    fn public_key_affiliated() {
        let message: &[u8] = b"Hello, world!";

        let mut rng = rand::thread_rng();
        let (pk, _) = generate_keypair(&mut rng);

        let cipher = pk.encrypt(&mut rng, message.into()).unwrap();
        assert!(pk.affiliated(&cipher));
    }

    #[test]
    fn public_key_not_affiliated() {
        let message: &[u8] = b"Hello, world!";

        let mut rng = rand::thread_rng();
        let (pk, _) = generate_keypair(&mut rng);
        let cipher = pk.encrypt(&mut rng, message.into()).unwrap();

        let (pk, _) = generate_keypair(&mut rng);
        assert!(!pk.affiliated(&cipher));
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_serialize() {
        let message: &[u8] = b"Hello, world!";

        let mut rng = rand::thread_rng();
        let (mut pk, mut sk) = generate_keypair(&mut rng);

        let cipher = pk.encrypt(&mut rng, message.into()).unwrap();
        let serialized = bincode::serialize(&cipher).unwrap();

        // Take care of the 8 extra bytes for the vec length thanks to bincode.
        assert_eq!(serialized.len(), 144 + 8 + message.len());
    }
}
