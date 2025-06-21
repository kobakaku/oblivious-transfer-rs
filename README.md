# Oblivious Transfer Implementation in Rust

This is a simplified implementation of 1-out-of-2 Oblivious Transfer (OT) protocol in Rust, designed for learning and proof-of-concept demonstrations.

## Generation and References

This code was generated with [Claude Code](https://claude.ai/code) 🤖

This implementation is based on standard OT protocols and references:
- Classical RSA-based OT protocol (Even, Goldreich, and Lempel)
- Receiver generates RSA key pair and sends blinded public keys
- Uses proper RSA assumption for security

## Features

- **1-out-of-2 Oblivious Transfer**: Sender has two messages, receiver chooses one without revealing which
- **Classical RSA-OT Protocol**: Uses the original Even-Goldreich-Lempel construction

### Current Limitations

- **No OT Extension**: Does not implement Ishai et al.'s OT extension protocol
- **Single OT Only**: Limited to one 1-out-of-2 transfer per protocol execution
- **No Batch Operations**: Cannot efficiently perform multiple OTs

## Usage

### Basic Example

```rust
use oblivious_transfer_rs::{OTSender, OTReceiver, Choice};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create messages (reasonable size for 1024-bit RSA keys)
    let message0 = b"Hello Alice!".to_vec();  // Message for choice 0
    let message1 = b"Hello Bob!!".to_vec();   // Message for choice 1
    
    // Setup sender and receiver
    let sender = OTSender::new(message0, message1)?;
    let mut receiver = OTReceiver::new(Choice::One); // Choose message 1
    
    // Phase 1: Receiver generates RSA keys using external crate (blackboxed)
    let public_keys = receiver.generate_public_keys()?;
    
    // Phase 2: Sender encrypts with external RSA crate, receiver decrypts chosen message
    let response = sender.encrypt_messages(public_keys)?;
    let decrypted = receiver.decrypt_message(response)?;
    
    println!("Received: {:?}", decrypted);
    Ok(())
}
```

### Running Tests

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_classical_rsa_ot_choice_zero
```

## Security Properties

### ✅ Security Guarantees

1. **Receiver Privacy**: Sender cannot determine which message the receiver chose
2. **Sender Privacy**: Receiver can only decrypt one of the two messages
3. **Fake Key Security**: Receiver generates fake public key but immediately discards the private key
4. **Cryptographic Randomness**: Uses `OsRng` for secure random number generation from external RSA library

### ⚠️ Learning/Research Limitations

This implementation is **NOT secure for production use** due to:

1. **Moderate RSA Key Size**: Uses 1024-bit keys for demonstration (acceptable for learning, not production)
2. **Basic RSA Padding**: Uses PKCS#1 v1.5 padding (less secure than OAEP for production)
4. **Simplified Protocol**: Missing advanced security features like:
   - Proof of knowledge protocols
   - Zero-knowledge proofs
   - Protection against malicious adversaries
5. **No Network Layer**: Runs locally only
6. **Limited Error Handling**: Basic error recovery

## Protocol Details

The implementation uses the classical RSA-based OT protocol (Even-Goldreich-Lempel):

1. **Receiver Setup**: 
   - Generates real RSA key pair: RsaPrivateKey::new() from external crate
   - Creates fake public key: Generates random RSA key pair but immediately discards the private key
   - Receiver retains only the real private key and both public keys
   - Uses 1024-bit keys from external RSA library (blackboxed)
   
2. **Public Key Blinding**:
   - Choice 0: pk0 = real_public_key, pk1 = fake_public_key
   - Choice 1: pk0 = fake_public_key, pk1 = real_public_key
   - Sender cannot distinguish which is the real public key
   - Receiver cannot decrypt messages encrypted with fake public key (private key was discarded)
   
3. **RSA Message Encryption**:
   - Sender encrypts m0 with pk0.encrypt(), m1 with pk1.encrypt() using external RSA crate
   - Uses PKCS#1 v1.5 padding scheme from external library
   
4. **RSA Message Decryption**:
   - Receiver uses private key: private_key.decrypt() from external RSA crate
   - Can only decrypt message encrypted with real public key
   - Message encrypted with fake key cannot be decrypted (receiver discarded the fake private key)

## License

This project is for learning and research purposes. Please implement proper security measures before any production use.