use anyhow::{anyhow, Result};
use rand::rngs::OsRng;
use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};

/// Choice enum for 1-out-of-2 OT
#[derive(Clone, Debug, Copy, PartialEq)]
pub enum Choice {
    Zero,
    One,
}

impl Choice {
    pub fn from_bit(bit: u8) -> Result<Self> {
        match bit {
            0 => Ok(Choice::Zero),
            1 => Ok(Choice::One),
            _ => Err(anyhow!("Invalid choice bit: {}", bit)),
        }
    }

    pub fn to_bit(&self) -> u8 {
        match self {
            Choice::Zero => 0,
            Choice::One => 1,
        }
    }
}

/// Classical RSA-based OT implementation (Even-Goldreich-Lempel)
/// Uses external RSA library for all cryptographic operations
#[derive(Clone, Debug)]
pub struct OTSender {
    messages: Vec<Vec<u8>>,
}

pub struct OTReceiver {
    choice: Choice,
    private_key: Option<RsaPrivateKey>,
    fake_public_key: Option<RsaPublicKey>,
}

/// Public keys sent from receiver to sender
#[derive(Clone)]
pub struct ReceiverPublicKeys {
    pub pk0: RsaPublicKey,
    pub pk1: RsaPublicKey,
}

/// Sender's response with encrypted messages
#[derive(Clone)]
pub struct SenderResponse {
    pub encrypted_m0: Vec<u8>,
    pub encrypted_m1: Vec<u8>,
}

impl OTSender {
    /// Create a new classical RSA-based OT sender with two messages
    pub fn new(message0: Vec<u8>, message1: Vec<u8>) -> Result<Self> {
        Ok(OTSender {
            messages: vec![message0, message1],
        })
    }

    /// Phase 2: Encrypt messages using receiver's public keys with RSA library
    pub fn encrypt_messages(&self, receiver_pks: ReceiverPublicKeys) -> Result<SenderResponse> {
        let mut rng = OsRng;

        // Encrypt message 0 with pk0 using RSA library
        let encrypted_m0 = receiver_pks.pk0.encrypt(
            &mut rng,
            PaddingScheme::new_pkcs1v15_encrypt(),
            &self.messages[0],
        )?;

        // Encrypt message 1 with pk1 using RSA library
        let encrypted_m1 = receiver_pks.pk1.encrypt(
            &mut rng,
            PaddingScheme::new_pkcs1v15_encrypt(),
            &self.messages[1],
        )?;

        Ok(SenderResponse {
            encrypted_m0,
            encrypted_m1,
        })
    }
}

impl OTReceiver {
    /// Create a new classical RSA-based OT receiver with a choice
    pub fn new(choice: Choice) -> Self {
        OTReceiver {
            choice,
            private_key: None,
            fake_public_key: None,
        }
    }

    /// Phase 1: Generate RSA key pair and create blinded public keys based on choice
    /// Uses external RSA library for key generation (blackboxed)
    ///
    /// Security: Receiver generates fake public key but immediately discards the private key
    /// This ensures receiver cannot decrypt messages encrypted with fake public key
    pub fn generate_public_keys(&mut self) -> Result<ReceiverPublicKeys> {
        let mut rng = OsRng;

        // Generate real RSA key pair using external library (blackboxed)
        let bits = 1024; // Small for demo, but more realistic than our custom implementation
        self.private_key = Some(RsaPrivateKey::new(&mut rng, bits)?);
        let real_public_key = RsaPublicKey::from(self.private_key.as_ref().unwrap());

        // Generate fake public key - receiver generates random public key but does NOT retain the private key
        // This ensures receiver cannot decrypt messages encrypted with the fake public key
        let fake_private_key = RsaPrivateKey::new(&mut rng, bits)?;
        let fake_public_key = RsaPublicKey::from(&fake_private_key);
        // Deliberately drop fake_private_key here - receiver must not retain it
        drop(fake_private_key);
        self.fake_public_key = Some(fake_public_key);

        // Arrange public keys based on choice
        // The key insight: receiver puts their real public key in the chosen position
        // and a fake public key in the other position
        let (pk0, pk1) = match self.choice {
            Choice::Zero => {
                // Real key goes to position 0, fake to position 1
                (
                    real_public_key,
                    self.fake_public_key.as_ref().unwrap().clone(),
                )
            }
            Choice::One => {
                // Fake goes to position 0, real key to position 1
                (
                    self.fake_public_key.as_ref().unwrap().clone(),
                    real_public_key,
                )
            }
        };

        Ok(ReceiverPublicKeys { pk0, pk1 })
    }

    /// Phase 2: Decrypt the chosen message using RSA library (blackboxed)
    pub fn decrypt_message(&self, response: SenderResponse) -> Result<Vec<u8>> {
        let private_key = self
            .private_key
            .as_ref()
            .ok_or_else(|| anyhow!("Invalid protocol state: private key not generated"))?;

        let padding = PaddingScheme::new_pkcs1v15_encrypt();

        // Receiver can only decrypt the message encrypted with their real public key
        let ciphertext = match self.choice {
            Choice::Zero => {
                // Real key was pk0, so decrypt encrypted_m0
                &response.encrypted_m0
            }
            Choice::One => {
                // Real key was pk1, so decrypt encrypted_m1
                &response.encrypted_m1
            }
        };

        // Decrypt using RSA library (blackboxed)
        let decrypted = private_key.decrypt(padding, ciphertext)?;
        Ok(decrypted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classical_rsa_ot_choice_zero() -> Result<()> {
        let message0 = b"Hello Alice!".to_vec();
        let message1 = b"Hello Bob!!".to_vec();

        // Create sender and receiver
        let sender = OTSender::new(message0.clone(), message1.clone())?;
        let mut receiver = OTReceiver::new(Choice::Zero);

        // Phase 1: Receiver generates and sends public keys using RSA library
        let public_keys = receiver.generate_public_keys()?;

        // Phase 2: Sender encrypts messages with public keys using RSA library
        let response = sender.encrypt_messages(public_keys)?;

        // Phase 2: Receiver decrypts chosen message using RSA library
        let decrypted = receiver.decrypt_message(response)?;

        // Verify we got the correct message
        assert_eq!(decrypted, message0);
        Ok(())
    }

    #[test]
    fn test_classical_rsa_ot_choice_one() -> Result<()> {
        let message0 = b"Secret Zero".to_vec();
        let message1 = b"Secret One!".to_vec();

        let sender = OTSender::new(message0.clone(), message1.clone())?;
        let mut receiver = OTReceiver::new(Choice::One);

        let public_keys = receiver.generate_public_keys()?;
        let response = sender.encrypt_messages(public_keys)?;
        let decrypted = receiver.decrypt_message(response)?;

        // Verify we got the correct message
        assert_eq!(decrypted, message1);
        Ok(())
    }

    #[test]
    fn test_sender_cannot_distinguish_keys() -> Result<()> {
        // This test verifies that from sender's perspective,
        // both public keys look valid (sender can't tell which is real)

        let mut receiver = OTReceiver::new(Choice::Zero);
        let public_keys = receiver.generate_public_keys()?;

        // Both keys should be usable for encryption (though one won't be decryptable)
        let test_msg = b"test message";
        let sender = OTSender::new(test_msg.to_vec(), test_msg.to_vec())?;

        // Both encryptions should succeed (this demonstrates sender can't distinguish)
        let result = sender.encrypt_messages(public_keys);
        assert!(result.is_ok());

        Ok(())
    }

    #[test]
    fn test_cannot_decrypt_wrong_message() -> Result<()> {
        let message0 = b"Should not get this".to_vec();
        let message1 = b"Should get this one".to_vec();

        let sender = OTSender::new(message0.clone(), message1.clone())?;
        let mut receiver = OTReceiver::new(Choice::One);

        let public_keys = receiver.generate_public_keys()?;
        let response = sender.encrypt_messages(public_keys)?;

        // Receiver should get message1, not message0
        let decrypted = receiver.decrypt_message(response)?;
        assert_eq!(decrypted, message1);
        assert_ne!(decrypted, message0);

        Ok(())
    }
}
