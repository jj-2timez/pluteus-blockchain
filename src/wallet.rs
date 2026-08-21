use hex;
use pqc_combo::{generate_dilithium_keypair, sign_message, verify_signature,
    DilithiumPublicKey, DilithiumSecretKey, DilithiumSignature,
};
use uuid::Uuid;
use crate::{extrinsic::{Context, Extrinsic}, ledger::Block};

pub struct Wallet {
    pub public_key: DilithiumPublicKey,
    pub private_key: DilithiumSecretKey,
}

impl Wallet {
    /// Generates a new post-quantum Dilithium / ML-DSA keypair.
    pub fn new() -> Self {
        let (public_key, private_key) = generate_dilithium_keypair();
        Self {
            public_key,
            private_key,
        }
    }

    /// Returns the public key encoded as a hexadecimal string.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key.as_ref())
    }

    /// Signs a Blake3 hash using the wallet's post-quantum private key.
    pub fn sign(&self, hash: &blake3::Hash) -> String {
        let signature: DilithiumSignature = sign_message(&self.private_key, hash.as_bytes());
        hex::encode(signature.as_ref())
    }

    /// Verifies an extrinsic's signature against its sender's public key.
    pub fn verify_signature(&self, extrinsic: &Extrinsic) -> bool {

       let Ok(public_key_bytes) = hex::decode(&extrinsic.sender_public_key) else { return false };
       let Ok(public_key_arr) = public_key_bytes.as_slice().try_into() else { return false };
       let public_key = DilithiumPublicKey::new(public_key_arr);

       let Ok(signiture_bytes) = hex::decode(&extrinsic.signature) else { return false };
       let Ok(signiture_arr) = signiture_bytes.as_slice().try_into() else { return false };
       let signiture = DilithiumSignature::new(signiture_arr);

       verify_signature(&public_key, extrinsic.hash_data().as_bytes(), &signiture)
    }

    /// Constructs, hashes, signs, and returns a new Extrinsic instance with optional payload.
    pub fn new_program_extrinsic(
        &self,
        receiver_public_key: String,
        amount: u64,
        transaction_context: Context,
        payload: Option<String>,
    ) -> Extrinsic {
        let timestamp = chrono::Utc::now().timestamp();

        let mut extrinsic = Extrinsic {
            sender_public_key: self.public_key_hex(),
            receiver_public_key,
            amount,
            id: Uuid::new_v4(),
            transaction_context,
            timestamp,
            signature: String::new(),
            payload,
        };

        let hash = extrinsic.hash_data();
        extrinsic.signature = self.sign(&hash);
        extrinsic
    }

    /// Constructs, hashes, signs, and returns a standard Extrinsic instance.
    pub fn new_extrinsic(
        &self,
        receiver_public_key: String,
        amount: u64,
        transaction_context: Context,
    ) -> Extrinsic {
        self.new_program_extrinsic(receiver_public_key, amount, transaction_context, None)
    }

    pub fn new_block(&self, transactions: Vec<Extrinsic>, previous_hash: String, block_height: u64) -> Block {
        let timestamp = chrono::Utc::now().timestamp() as u64;
        let mut block = Block {
            transactions,
            previous_hash,
            signer: self.public_key_hex(),
            block_height,
            timestamp,
            signature: String::new(),
        };
        let hash = block.hash_data();
        block.signature = self.sign(&hash);

        block
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_creation() {
        let wallet = Wallet::new();
        assert!(!wallet.public_key_hex().is_empty());
    }

    #[test]
    fn test_new_extrinsic_and_verification() {
        let sender = Wallet::new();
        let receiver = Wallet::new();

        let extrinsic = sender.new_extrinsic(
            receiver.public_key_hex(),
            100,
            Context::TransferAssets,
        );

        assert!(sender.verify_signature(&extrinsic));
    }

    #[test]
    fn test_verify_signature_tampered_amount() {
        let sender = Wallet::new();
        let receiver = Wallet::new();

        let mut extrinsic = sender.new_extrinsic(
            receiver.public_key_hex(),
            100,
            Context::TransferAssets,
        );
        
        extrinsic.amount = 9999;

        assert!(!sender.verify_signature(&extrinsic));
    }

    #[test]
    fn test_verify_signature_invalid_sender_key() {
        let sender = Wallet::new();
        let receiver = Wallet::new();
        let attacker = Wallet::new();

        let mut extrinsic = sender.new_extrinsic(
            receiver.public_key_hex(),
            100,
            Context::TransferAssets,
        );

        extrinsic.sender_public_key = attacker.public_key_hex();

        assert!(!sender.verify_signature(&extrinsic));
    }

    #[test]
    fn test_extrinsic_rkyv_roundtrip() {
        let sender = Wallet::new();
        let receiver = Wallet::new();

        let extrinsic = sender.new_extrinsic(
            receiver.public_key_hex(),
            500,
            Context::ExchangeAssets,
        );

        let bytes = extrinsic.to_bytes().expect("Failed to serialize Extrinsic");
        let deserialized = Extrinsic::from_bytes(&bytes).expect("Failed to deserialize Extrinsic");

        assert_eq!(extrinsic, deserialized);
        assert!(sender.verify_signature(&deserialized));
    }

    #[test]
    fn test_program_extrinsic_signing_and_verification() {
        let sender = Wallet::new();
        let program_id = "custom_program_hash_123".to_string();
        let payload = Some("{\"action\":\"mint\",\"amount\":500}".to_string());

        let extrinsic = sender.new_program_extrinsic(
            program_id,
            0,
            Context::ExecuteProgram,
            payload,
        );

        assert!(sender.verify_signature(&extrinsic));

        let bytes = extrinsic.to_bytes().expect("Serialization should succeed");
        let decoded = Extrinsic::from_bytes(&bytes).expect("Deserialization should succeed");
        assert_eq!(extrinsic, decoded);
        assert!(sender.verify_signature(&decoded));
    }
}