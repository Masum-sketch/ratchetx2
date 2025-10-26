use ratchetx2::{SharedKeys, Ratchetx2};
use x25519_dalek::StaticSecret;
use ring::rand::{SystemRandom, SecureRandom};

#[test]
fn test_ratchetx2_serialization_roundtrip() {
    // Generate random keys
    let rng = SystemRandom::new();
    let mut secret_key_bytes = [0u8; 32];
    let mut header_key_alice_bytes = [0u8; 32];
    let mut header_key_bob_bytes = [0u8; 32];
    rng.fill(&mut secret_key_bytes).unwrap();
    rng.fill(&mut header_key_alice_bytes).unwrap();
    rng.fill(&mut header_key_bob_bytes).unwrap();

    // Create shared keys
    let shared_keys = SharedKeys {
        secret_key: secret_key_bytes,
        header_key_alice: header_key_alice_bytes,
        header_key_bob: header_key_bob_bytes,
    };

    // Create Bob's static secret
    let mut bob_secret_bytes = [0u8; 32];
    rng.fill(&mut bob_secret_bytes).unwrap();
    let bob_secret = StaticSecret::from(bob_secret_bytes);

    // Initialize Bob using static secret (serializable)
    let mut bob = shared_keys.bob_from_static_secret(bob_secret);
    
    // Initialize Alice
    let alice = shared_keys.alice(&bob.public_key());

    // Perform some ratchet steps (this gives Bob a Dalek key)
    bob.step_dh_root(&alice.public_key());
    let msg_key1 = bob.step_msgs();
    
    // Now Bob should be fully serializable after DH ratchet step
    // Serialize Bob's state using bincode 2.0
    let config = bincode::config::standard();
    let serialized = bincode::encode_to_vec(&bob, config)
        .expect("Failed to serialize Bob");
    println!("Serialized Bob state: {} bytes", serialized.len());

    // Deserialize Bob's state
    let (mut bob_restored, _): (Ratchetx2, usize) = bincode::decode_from_slice(&serialized, config)
        .expect("Failed to deserialize Bob");

    // Verify both states produce the same message keys
    let original_key = bob.step_msgs();
    let restored_key = bob_restored.step_msgs();
    assert_eq!(original_key, restored_key, "Restored state should produce same message keys");

    println!("✅ Serialization roundtrip successful!");
}

#[test]
fn test_serialize_bob_with_static_secret() {
    // Generate keys
    let rng = SystemRandom::new();
    let mut secret_key_bytes = [0u8; 32];
    let mut header_key_alice_bytes = [0u8; 32];
    let mut header_key_bob_bytes = [0u8; 32];
    rng.fill(&mut secret_key_bytes).unwrap();
    rng.fill(&mut header_key_alice_bytes).unwrap();
    rng.fill(&mut header_key_bob_bytes).unwrap();

    let shared_keys = SharedKeys {
        secret_key: secret_key_bytes,
        header_key_alice: header_key_alice_bytes,
        header_key_bob: header_key_bob_bytes,
    };

    // Create Bob with static secret (serializable)
    let mut bob_secret_bytes = [0u8; 32];
    rng.fill(&mut bob_secret_bytes).unwrap();
    let bob_secret = StaticSecret::from(bob_secret_bytes);
    let bob = shared_keys.bob_from_static_secret(bob_secret);

    // Serialize Bob (should work since using Dalek variant)
    let config = bincode::config::standard();
    let serialized = bincode::encode_to_vec(&bob, config)
        .expect("Failed to serialize Bob with Dalek key");
    println!("Serialized Bob state (Dalek): {} bytes", serialized.len());

    // Deserialize and verify
    let (bob_restored, _): (Ratchetx2, usize) = bincode::decode_from_slice(&serialized, config)
        .expect("Failed to deserialize Bob");
    println!("✅ Bob serialization successful!");
}
