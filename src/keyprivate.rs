//! Key private versions of the forward secure encryption scheme.
//!
//! The key privacy ensures that you cannot link a ciphertext to the public key that has generated
//! it, without knowledge of the secret key that belongs to the public key. Since the actual FS-PKE
//! scheme does not provide key privacy, we "add" it by encrypting the important part with key
//! privacy.
//!
//! Note that this "key hiding" only works when serde is also used, as we encrypt the inner key
//! with a symmetric AES cipher.
use super::{Aes128Ctr64LE, RatchetError, IV};

use aes::cipher::{KeyIvInit, StreamCipher};
use curve25519_dalek::{constants::X25519_BASEPOINT, montgomery::MontgomeryPoint, scalar::Scalar};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use sha3::Digest;

/// Ciphertext representation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ciphertext {
    dh_prekey: MontgomeryPoint,
    payload: Vec<u8>,
}

/// Structure representing a ratchetable public key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    inner_key: super::PublicKey,
    outer_key: MontgomeryPoint,
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
        self.inner_key.ratchet()
    }

    /// Encrypt the given payload.
    pub fn encrypt<R: Rng + CryptoRng>(
        &self,
        mut rng: R,
        payload: Vec<u8>,
    ) -> Result<Ciphertext, RatchetError> {
        // Step 1: Inner encryption
        let ciphertext = self.inner_key.encrypt(&mut rng, payload)?;
        let mut ciphertext = bincode::serialize(&ciphertext).unwrap();

        // Step 2: Apply outer encryption
        let epheremal_secret = Scalar::random(&mut rng);
        let epheremal_key = X25519_BASEPOINT * epheremal_secret;
        let shared_secret = self.outer_key * epheremal_secret;
        let aes_key = kdf(&shared_secret);
        let mut cipher = Aes128Ctr64LE::new(&aes_key.into(), &IV.into());
        cipher.apply_keystream(&mut ciphertext);

        Ok(Ciphertext {
            dh_prekey: epheremal_key,
            payload: ciphertext,
        })
    }
}

/// Structure representing a ratchetable private key.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateKey {
    inner_key: super::PrivateKey,
    outer_key: Scalar,
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
    pub fn ratchet<R: Rng + CryptoRng>(&mut self, rng: R) -> Result<(), RatchetError> {
        self.inner_key.ratchet(rng)
    }

    pub fn decrypt(&self, mut ciphertext: Ciphertext) -> Result<Vec<u8>, RatchetError> {
        // Step 1: Remove the outer layer of encryption
        let shared_secret = ciphertext.dh_prekey * self.outer_key;
        let aes_key = kdf(&shared_secret);
        let mut cipher = Aes128Ctr64LE::new(&aes_key.into(), &IV.into());
        cipher.apply_keystream(&mut ciphertext.payload);

        // Step 2: Do the decryption of the inner FS-PKE
        let ciphertext: super::Ciphertext = bincode::deserialize(&ciphertext.payload).unwrap();
        self.inner_key.decrypt(ciphertext)
    }
}

/// Wraps a non-key-private FS-PKE key in a key private version.
pub fn wrap_keypair<R: Rng + CryptoRng>(
    mut rng: R,
    keypair: (super::PublicKey, super::PrivateKey),
) -> (PublicKey, PrivateKey) {
    let priv_key = Scalar::random(&mut rng);
    let pub_key = X25519_BASEPOINT * priv_key;
    (
        PublicKey {
            inner_key: keypair.0,
            outer_key: pub_key,
        },
        PrivateKey {
            inner_key: keypair.1,
            outer_key: priv_key,
        },
    )
}

fn kdf(group_element: &MontgomeryPoint) -> [u8; 16] {
    let mut hasher = sha3::Sha3_256::new();
    hasher.update(group_element.to_bytes());
    let result: [u8; 32] = hasher.finalize().into();
    result[..16].try_into().unwrap()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn message_roundtrip() {
        let message: &[u8] = b"Hello, world!";

        let mut rng = rand::thread_rng();
        let keypair = crate::generate_keypair(&mut rng);
        let (mut pk, mut sk) = wrap_keypair(&mut rng, keypair);

        let cipher = pk.encrypt(&mut rng, message.into()).unwrap();
        let plain = sk.decrypt(cipher).unwrap();
        assert_eq!(plain, message);

        pk.ratchet().unwrap();
        sk.ratchet(&mut rng).unwrap();

        let cipher = pk.encrypt(&mut rng, message.into()).unwrap();
        let plain = sk.decrypt(cipher).unwrap();
        assert_eq!(plain, message);
    }
}
