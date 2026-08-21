use rkyv::{Archive, Deserialize, Serialize};
use uuid::Uuid;

#[derive(Hash, Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub enum Context {
    ExchangeAssets,
    TransferAssets,
    DeployProgram,
    ExecuteProgram,
}

#[derive(Hash, Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub struct Extrinsic {
    pub sender_public_key: String,
    pub receiver_public_key: String,
    pub amount: u64,
    pub id: Uuid,
    pub transaction_context: Context,
    pub timestamp: i64,
    pub signature: String,
    pub payload: Option<String>,
}

impl Extrinsic {
    /// Hashes the critical transaction fields (excluding the signature itself) using Blake3.
    pub fn hash_data(&self) -> blake3::Hash {
        let mut hasher = blake3::Hasher::new();

        // Feed fields directly into Blake3 (Zero-copy, No allocations)
        hasher.update(self.sender_public_key.as_bytes());
        hasher.update(self.receiver_public_key.as_bytes());
        hasher.update(&self.amount.to_le_bytes());
        hasher.update(self.id.as_bytes());

        // Map the Context Enum to a distinct byte
        let ctx_byte = match self.transaction_context {
            Context::ExchangeAssets => 0u8,
            Context::TransferAssets => 1u8,
            Context::DeployProgram => 2u8,
            Context::ExecuteProgram => 3u8,
        };
        hasher.update(&[ctx_byte]);

        hasher.update(&self.timestamp.to_le_bytes());

        if let Some(payload) = &self.payload {
            hasher.update(payload.as_bytes());
        }

        hasher.finalize()
    }

    /// Serializes the entire Extrinsic struct to raw bytes using rkyv.
    pub fn to_bytes(&self) -> Result<rkyv::util::AlignedVec, rkyv::rancor::Error> {
        rkyv::to_bytes::<rkyv::rancor::Error>(self)
    }

    /// Deserializes an Extrinsic struct from raw bytes using rkyv.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, rkyv::rancor::Error> {
        rkyv::from_bytes::<Self, rkyv::rancor::Error>(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extrinsic_rkyv_roundtrip_with_program_context() {
        let extrinsic = Extrinsic {
            sender_public_key: "sender_hex_123".to_string(),
            receiver_public_key: "program_id_456".to_string(),
            amount: 50,
            id: Uuid::new_v4(),
            transaction_context: Context::ExecuteProgram,
            timestamp: 123456789,
            signature: "sig_abc".to_string(),
            payload: Some("payload_args_here".to_string()),
        };

        let bytes = extrinsic.to_bytes().expect("Should serialize extrinsic");
        let decoded = Extrinsic::from_bytes(&bytes).expect("Should deserialize extrinsic");

        assert_eq!(extrinsic, decoded);
        assert_eq!(extrinsic.hash_data(), decoded.hash_data());
    }

    #[test]
    fn test_deploy_program_extrinsic_hashing() {
        let ext1 = Extrinsic {
            sender_public_key: "sender1".to_string(),
            receiver_public_key: "prog1".to_string(),
            amount: 0,
            id: Uuid::new_v4(),
            transaction_context: Context::DeployProgram,
            timestamp: 1000,
            signature: "".to_string(),
            payload: Some("def execute(sender, payload): return {}".to_string()),
        };

        let mut ext2 = ext1.clone();
        ext2.payload = Some("def execute(sender, payload): return {'status': 'ok'}".to_string());

        assert_ne!(ext1.hash_data(), ext2.hash_data());
    }
}