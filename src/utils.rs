// This module contains utility functions for Ethereum signature operations

use sha3::{Digest, Keccak256};

// Computes the Keccak-256 hash of the given data
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

// Prepares an Ethereum-specific message for signing by adding a prefix
pub fn eth_message(message: &str) -> Vec<u8> {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut eth_message = prefix.as_bytes().to_vec();
    eth_message.extend_from_slice(message.as_bytes());
    eth_message
}

// Derives the Ethereum address from the public key
pub fn get_ethereum_address(public_key_hex: &String) -> Result<String, Box<dyn std::error::Error>> {
    let public_key_bytes = hex::decode(public_key_hex)?;

    let mut hasher = Keccak256::new();
    hasher.update(&public_key_bytes[1..]);
    let hash = hasher.finalize();

    let address_bytes = &hash[12..];
    Ok(format!("0x{}", hex::encode(address_bytes)))
}
