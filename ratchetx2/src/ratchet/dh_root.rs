use crate::key::{ChainKey, HeaderKey, RootKey, SecretKey};
use ring::agreement::{EphemeralPrivateKey, UnparsedPublicKey, X25519, agree_ephemeral};
use ring::hkdf::{HKDF_SHA256, Salt};
use ring::rand::SystemRandom;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// DH private key that can be either ring's EphemeralPrivateKey or x25519-dalek's StaticSecret
enum DhPrivateKey {
    Ring(EphemeralPrivateKey),
    Dalek(X25519StaticSecret),
}

impl std::fmt::Debug for DhPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DhPrivateKey::Ring(_) => f.write_str("DhPrivateKey::Ring(...)"),
            DhPrivateKey::Dalek(_) => f.write_str("DhPrivateKey::Dalek(...)"),
        }
    }
}

impl DhPrivateKey {
    fn compute_public_key(&self) -> Vec<u8> {
        match self {
            DhPrivateKey::Ring(key) => key.compute_public_key().unwrap().as_ref().to_vec(),
            DhPrivateKey::Dalek(key) => X25519PublicKey::from(key).as_bytes().to_vec(),
        }
    }

    fn agree(&self, peer_public: &[u8]) -> Vec<u8> {
        match self {
            DhPrivateKey::Ring(key) => {
                let key_copy = unsafe { core::mem::transmute_copy(key) };
                agree_ephemeral(
                    key_copy,
                    &UnparsedPublicKey::new(&X25519, peer_public),
                    |k| k.to_vec(),
                ).unwrap()
            }
            DhPrivateKey::Dalek(key) => {
                let peer_public_array: [u8; 32] = peer_public.try_into().expect("invalid public key length");
                let peer_public_key = X25519PublicKey::from(peer_public_array);
                key.diffie_hellman(&peer_public_key).as_bytes().to_vec()
            }
        }
    }

    fn generate_ring() -> Self {
        DhPrivateKey::Ring(EphemeralPrivateKey::generate(&X25519, &SystemRandom::new()).unwrap())
    }
}

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub(super) struct DhRootRatchet {
    root_key: RootKey,
    #[zeroize(skip)]
    private_key: DhPrivateKey,
    /// - true: next step will update private key
    /// - false: next step will not update private key
    update_private_key: bool,
}

impl PartialEq for DhRootRatchet {
    fn eq(&self, other: &Self) -> bool {
        let self_public_key = self.private_key.compute_public_key();
        let other_public_key = other.private_key.compute_public_key();
        let self_dh = self.private_key.agree(&other_public_key);
        let other_dh = other.private_key.agree(&self_public_key);
        self.root_key == other.root_key && self_dh == other_dh
    }
}

impl DhRootRatchet {
    /// New a DhRootRatchet for Alice.
    pub fn alice(secret_key: SecretKey) -> Self {
        Self {
            root_key: secret_key,
            private_key: DhPrivateKey::generate_ring(),
            update_private_key: false,
        }
    }

    /// New a DhRootRatchet for Bob (ring::EphemeralPrivateKey).
    pub fn bob(secret_key: SecretKey, private_key: EphemeralPrivateKey) -> Self {
        Self {
            root_key: secret_key,
            private_key: DhPrivateKey::Ring(private_key),
            update_private_key: true,
        }
    }

    /// New a DhRootRatchet for Bob from x25519-dalek StaticSecret (serializable).
    pub fn bob_from_static_secret(secret_key: SecretKey, private_key: X25519StaticSecret) -> Self {
        Self {
            root_key: secret_key,
            private_key: DhPrivateKey::Dalek(private_key),
            update_private_key: true,
        }
    }

    /// New a DhRootRatchet for Bob from raw 32 bytes.
    pub fn bob_from_bytes(secret_key: SecretKey, private_key_bytes: &[u8; 32]) -> Self {
        Self {
            root_key: secret_key,
            private_key: DhPrivateKey::Dalek(X25519StaticSecret::from(*private_key_bytes)),
            update_private_key: true,
        }
    }

    /// Get current publict key.
    pub fn public_key(&self) -> Vec<u8> {
        self.private_key.compute_public_key()
    }

    /// Perform ratchet step, update DH pair if needed, update RootKey, and return current ChainKey, next HeaderKey.
    pub fn step(&mut self, public_key: &[u8]) -> (ChainKey, HeaderKey) {
        let dh_output = self.private_key.agree(public_key);
        
        if self.update_private_key {
            self.private_key = DhPrivateKey::generate_ring();
        }
        self.update_private_key = !self.update_private_key;

        let salt = Salt::new(HKDF_SHA256, &self.root_key);
        let prk = salt.extract(&dh_output);
        let okm = prk.expand(&[b"RootKey"], HKDF_SHA256).unwrap();
        let mut root_key = RootKey::default();
        okm.fill(&mut root_key).unwrap();
        self.root_key = root_key;
        let okm = prk.expand(&[b"ChainKey"], HKDF_SHA256).unwrap();
        let mut chain_key = ChainKey::default();
        okm.fill(&mut chain_key).unwrap();
        let okm = prk.expand(&[b"HeaderKey"], HKDF_SHA256).unwrap();
        let mut header_key = HeaderKey::default();
        okm.fill(&mut header_key).unwrap();
        (chain_key, header_key)
    }
}
