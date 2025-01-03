// Main entry point for Ethereum signing and validation example

mod keypair;
mod signature;
mod utils;

use keypair::generate_eth_keypair;
use signature::{create_signature, validate_signature};
use utils::get_ethereum_address;

fn main() {
    let key_pair = generate_eth_keypair();
    println!("Private Key: {}", key_pair.private_key);
    println!("Public Key: {}", key_pair.public_key);

    let message = "Sign in at UTU";
    println!("\nSigning message: {}", message);

    match create_signature(key_pair.private_key.clone(), message.to_string()) {
        Ok(signature) => match get_ethereum_address(&key_pair.public_key) {
            Ok(address) => {
                println!("\nGenerated address: {}", address);
                match validate_signature(signature.clone(), address.clone(), message.to_string()) {
                    Ok(is_valid) => {
                        println!("\nSignature: {}", signature);
                        println!("Is signature valid? {}", is_valid);

                        if !is_valid {
                            panic!("Signature validation failed!");
                        }
                    }
                    Err(e) => println!("Validation error: {}", e),
                }
            }
            Err(e) => println!("Address generation error: {}", e),
        },
        Err(e) => println!("Signature creation error: {}", e),
    }
}
