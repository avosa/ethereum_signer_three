// This is the library entry point that includes all the modules
// and calls the functions to generate a key pair, sign a message,
// and validate the signature. The keypair module generates a new
// Ethereum key pair, the signature module creates and validates
// Ethereum signatures, and the utils module contains utility
// functions for Ethereum signature operations.

pub mod keypair;
pub mod signature;
pub mod utils;
