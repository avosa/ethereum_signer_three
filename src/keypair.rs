// This module handles Ethereum key pair generation

use ecdsa::SigningKey;
use hex::encode;
use k256::Secp256k1;
use rand_core::OsRng;

// Represents an Ethereum key pair with private and public keys
pub struct EthKeyPair {
    pub private_key: String,
    pub public_key: String,
}

pub fn generate_eth_keypair() -> EthKeyPair {
    // Generate a new signing key - note we are using the OsRng seed. ICP smart
    // contracts do not allow us to use random() therefore we need to call a canister
    // to get the random needed by SigningKey instead (when porting this code to ICP)
    let signing_key: SigningKey<Secp256k1> = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let private_key_hex = encode(signing_key.to_bytes());
    // Store the encoded_point before getting bytes to keep it alive long enough.
    // This is a Rust lifetime requirement - the as_bytes() result must not outlive
    // the encoded_point.
    let encoded_point = verifying_key.to_encoded_point(false);
    let public_key_bytes = encoded_point.as_bytes();

    println!("public_key_bytes: {:#?}", public_key_bytes);
    let public_key_hex = encode(public_key_bytes);

    EthKeyPair {
        private_key: private_key_hex,
        public_key: public_key_hex,
    }
}
