# Secure RSA-based Oblivious Transfer with XOR Masking

This is an implementation of 1-out-of-2 Oblivious Transfer (OT) protocol in Rust with enhanced security using XOR masking, designed for learning and research purposes.

## Generation and References

This code was generated with [Claude Code](https://claude.ai/code) 🤖

This implementation uses a modified RSA-based OT protocol with XOR masking:
- Sender generates RSA key pair and performs XOR masking
- Receiver creates encrypted values based on choice
- Enhanced security compared to classical EGL protocol

## Features

- **1-out-of-2 Oblivious Transfer**: Sender has two messages, receiver chooses one without revealing which
- **RSA-based Protocol with XOR Masking**: Enhanced security using XOR operations
- **Blackboxed XOR Operations**: XOR functions separated into dedicated module
- **2048-bit RSA Keys**: Improved security with larger key size

### Current Limitations

- **No OT Extension**: Does not implement OT extension protocols
- **Single OT Only**: Limited to one 1-out-of-2 transfer per protocol execution
- **No Batch Operations**: Cannot efficiently perform multiple OTs
- **PKCS#1 v1.5 Padding**: Uses older padding scheme (not OAEP)

## Usage

### Basic Example

```rust
use oblivious_transfer_rs::{OTSender, OTReceiver, Choice};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create messages
    let message0 = b"Hello Alice!".to_vec();  // Message for choice 0
    let message1 = b"Hello Bob!!".to_vec();   // Message for choice 1
    
    // Setup sender and receiver
    let mut sender = OTSender::new(message0, message1)?;
    let mut receiver = OTReceiver::new(Choice::One); // Choose message 1
    
    // Phase 1: Sender generates RSA key pair
    let sender_pk = sender.generate_keys()?;
    
    // Phase 2: Receiver generates encrypted values (C0, C1)
    let encrypted_values = receiver.generate_encrypted_values(sender_pk)?;
    
    // Phase 3: Sender decrypts and creates masked messages (K0, K1)
    let masked_messages = sender.create_masked_messages(encrypted_values)?;
    
    // Phase 4: Receiver extracts chosen message
    let decrypted = receiver.extract_message(masked_messages)?;
    
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
cargo test test_rsa_ot_with_xor_choice_zero

# Test XOR module separately
cargo test xor::tests
```

## Protocol Details

The implementation uses an enhanced RSA-based OT protocol with XOR masking:

### Phase 1: Key Generation
1. **Sender** generates RSA key pair (pk, sk) using 2048-bit keys
2. Sender sends public key (pk) to Receiver

### Phase 2: Receiver Preparation
1. **Receiver** generates random value `x`
2. Based on choice bit `b`:
   - If `b=0`: `y0=x`, `y1=random`
   - If `b=1`: `y0=random`, `y1=x`
3. Receiver encrypts: `C0 = Enc_pk(y0)`, `C1 = Enc_pk(y1)`
4. Sends `(C0, C1)` to Sender

### Phase 3: Message Masking
1. **Sender** decrypts: `decrypted_C0 = Dec_sk(C0)`, `decrypted_C1 = Dec_sk(C1)`
2. Creates masked messages:
   - `K0 = decrypted_C0 ⊕ m0`
   - `K1 = decrypted_C1 ⊕ m1`
3. Sends `(K0, K1)` to Receiver

### Phase 4: Message Extraction
1. **Receiver** extracts chosen message:
   - If `b=0`: `m0 = K0 ⊕ x`
   - If `b=1`: `m1 = K1 ⊕ x`


## License

This project is for learning and research purposes. Please implement proper security measures before any production use.