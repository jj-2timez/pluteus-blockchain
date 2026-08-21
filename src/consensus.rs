use crate::wallet::Wallet;
use pqc_combo::{verify_signature, DilithiumPublicKey, DilithiumSignature, ML_DSA_65_PK_BYTES};
use rkyv::{Archive, Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub enum Phase {
    Open,
    Nominate,
    Prepare,
    Commit,
    Externalized,
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub enum MessageType {
    Nominate,
    Prepare,
    Commit,
    Externalize,
}

#[derive(Clone, Default)]
pub struct QuorumSet {
    pub threshold: usize,
    pub validators: Vec<DilithiumPublicKey>,
}

impl QuorumSet {
    pub fn new(threshold: usize, validators: Vec<DilithiumPublicKey>) -> Self {
        Self { threshold, validators }
    }

    /// Checks if the provided node votes meet the threshold by comparing byte references
    pub fn is_quorum_slice(&self, nodes: &[DilithiumPublicKey]) -> bool {
        if self.threshold == 0 {
            return true;
        }
        let matches = self
            .validators
            .iter()
            .filter(|val| nodes.iter().any(|n| n.as_ref() == val.as_ref()))
            .count();

        matches >= self.threshold
    }
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub struct ConsensusMessage {
    pub slot: u64,
    pub sender_id: String,
    pub msg_type: MessageType,
    pub value: String,
    pub signature: Option<String>,
}

impl ConsensusMessage {
    pub fn new(slot: u64, sender_id: String, msg_type: MessageType, value: String) -> Self {
        Self {
            slot,
            sender_id,
            msg_type,
            value,
            signature: None,
        }
    }

    pub fn to_bytes(&self) -> Result<rkyv::util::AlignedVec, rkyv::rancor::Error> {
        rkyv::to_bytes::<rkyv::rancor::Error>(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, rkyv::rancor::Error> {
        rkyv::from_bytes::<Self, rkyv::rancor::Error>(bytes)
    }

    pub fn hash_data(&self) -> blake3::Hash {
        let mut hasher = blake3::Hasher::new();

        // Feed fields directly into Blake3
        hasher.update(&self.slot.to_le_bytes());
        hasher.update(self.sender_id.as_bytes());

        // Map the MessageType Enum to a distinct byte
        let msg_type_byte = match self.msg_type {
            MessageType::Nominate => 0u8,
            MessageType::Prepare => 1u8,
            MessageType::Commit => 2u8,
            MessageType::Externalize => 3u8,
        };
        hasher.update(&[msg_type_byte]);

        hasher.update(self.value.as_bytes());

        hasher.finalize()
    }

    pub fn sign(&mut self, wallet: &Wallet) {
        let hash = self.hash_data();
        self.signature = Some(wallet.sign(&hash));
    }

    pub fn verify_signature(&self) -> bool {
        let Some(sig_hex) = &self.signature else {
            return false;
        };

        let hash = self.hash_data();

        let Ok(pk_bytes) = hex::decode(&self.sender_id) else {
            return false;
        };
        let Ok(pk_arr) = pk_bytes.as_slice().try_into() else {
            return false;
        };
        let pk = DilithiumPublicKey::new(pk_arr);

        let Ok(sig_bytes) = hex::decode(sig_hex) else {
            return false;
        };
        let Ok(sig_arr) = sig_bytes.as_slice().try_into() else {
            return false;
        };
        let sig = DilithiumSignature::new(sig_arr);

        verify_signature(&pk, hash.as_bytes(), &sig)
    }
}

/// Helper function to push unique keys into a Vec (mimicking HashSet behavior)
fn add_vote(votes: &mut Vec<DilithiumPublicKey>, pk: &DilithiumPublicKey) {
    if !votes.iter().any(|v| v.as_ref() == pk.as_ref()) {
        votes.push(pk.clone());
    }
}

#[derive(Clone)]
pub struct SlotState {
    pub slot: u64,
    pub phase: Phase,
    pub nominations: BTreeMap<String, Vec<DilithiumPublicKey>>,
    pub prepare_votes: BTreeMap<String, Vec<DilithiumPublicKey>>,
    pub commit_votes: BTreeMap<String, Vec<DilithiumPublicKey>>,
    pub externalized_value: Option<String>,
}

impl SlotState {
    pub fn new(slot: u64) -> Self {
        Self {
            slot,
            phase: Phase::Open,
            nominations: BTreeMap::new(),
            prepare_votes: BTreeMap::new(),
            commit_votes: BTreeMap::new(),
            externalized_value: None,
        }
    }
}

#[derive(Clone)]
pub struct Consensus {
    pub node_id: String,
    pub node_pk: DilithiumPublicKey,
    pub quorum_set: QuorumSet,
    pub current_slot: u64,
    pub slot_states: BTreeMap<u64, SlotState>,
}

impl Consensus {
    pub fn new(node_id: String, quorum_set: QuorumSet, initial_slot: u64) -> Self {
        let mut slot_states = BTreeMap::new();
        slot_states.insert(initial_slot, SlotState::new(initial_slot));

        let pk_bytes = hex::decode(&node_id).expect("node_id must be valid hex");
        let pk_arr: [u8; ML_DSA_65_PK_BYTES] = pk_bytes
            .as_slice()
            .try_into()
            .expect("node_id must have valid ML-DSA PK length");
        let node_pk = DilithiumPublicKey::new(pk_arr);

        Self {
            node_id,
            node_pk,
            quorum_set,
            current_slot: initial_slot,
            slot_states,
        }
    }

    pub fn start_slot(&mut self, slot: u64) {
        self.current_slot = slot;
        self.slot_states.entry(slot).or_insert_with(|| SlotState::new(slot));
    }

    pub fn get_slot_state(&self, slot: u64) -> Option<&SlotState> {
        self.slot_states.get(&slot)
    }

    pub fn is_slot_externalized(&self, slot: u64) -> bool {
        self.slot_states
            .get(&slot)
            .map(|s| s.phase == Phase::Externalized)
            .unwrap_or(false)
    }

    pub fn get_externalized_value(&self, slot: u64) -> Option<&str> {
        self.slot_states
            .get(&slot)
            .and_then(|s| s.externalized_value.as_deref())
    }

    // --- Core Action Methods ---

    pub fn nominate(&mut self, slot: u64, value: String) -> Result<ConsensusMessage, String> {
        let state = self.slot_states.entry(slot).or_insert_with(|| SlotState::new(slot));

        if state.phase == Phase::Externalized {
            return Err(format!("Slot {} is already externalized", slot));
        }
        if state.phase == Phase::Open {
            state.phase = Phase::Nominate;
        }

        let voters = state.nominations.entry(value.clone()).or_default();
        add_vote(voters, &self.node_pk);

        let msg = ConsensusMessage::new(
            slot,
            self.node_id.clone(),
            MessageType::Nominate,
            value.clone(),
        );
        self.check_state_transitions(slot, &value);
        Ok(msg)
    }

    pub fn prepare(&mut self, slot: u64, value: String) -> Result<ConsensusMessage, String> {
        let state = self.slot_states.entry(slot).or_insert_with(|| SlotState::new(slot));

        if state.phase == Phase::Externalized {
            return Err(format!("Slot {} is already externalized", slot));
        }

        state.phase = Phase::Prepare;

        let voters = state.prepare_votes.entry(value.clone()).or_default();
        add_vote(voters, &self.node_pk);

        let msg = ConsensusMessage::new(
            slot,
            self.node_id.clone(),
            MessageType::Prepare,
            value.clone(),
        );
        self.check_state_transitions(slot, &value);
        Ok(msg)
    }

    pub fn commit(&mut self, slot: u64, value: String) -> Result<ConsensusMessage, String> {
        let state = self.slot_states.entry(slot).or_insert_with(|| SlotState::new(slot));

        if state.phase == Phase::Externalized {
            return Err(format!("Slot {} is already externalized", slot));
        }

        state.phase = Phase::Commit;

        let voters = state.commit_votes.entry(value.clone()).or_default();
        add_vote(voters, &self.node_pk);

        let msg = ConsensusMessage::new(
            slot,
            self.node_id.clone(),
            MessageType::Commit,
            value.clone(),
        );
        self.check_state_transitions(slot, &value);
        Ok(msg)
    }

    // --- Message Processing ---

    pub fn process_message(
        &mut self,
        msg: ConsensusMessage,
    ) -> Result<Option<ConsensusMessage>, String> {
        if !msg.verify_signature() {
            return Err("Invalid cryptographic signature on consensus message".to_string());
        }

        let pk_bytes = hex::decode(&msg.sender_id).map_err(|_| "Invalid hex in sender_id")?;
        let pk_arr: [u8; ML_DSA_65_PK_BYTES] = pk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid PK size")?;
        let sender_pk = DilithiumPublicKey::new(pk_arr);

        let state = self
            .slot_states
            .entry(msg.slot)
            .or_insert_with(|| SlotState::new(msg.slot));
        if state.phase == Phase::Externalized {
            return Ok(None);
        }

        let initial_phase = state.phase;

        match msg.msg_type {
            MessageType::Nominate => {
                let list = state.nominations.entry(msg.value.clone()).or_default();
                add_vote(list, &sender_pk);
            }
            MessageType::Prepare => {
                let nom_list = state.nominations.entry(msg.value.clone()).or_default();
                add_vote(nom_list, &sender_pk);
                let prep_list = state.prepare_votes.entry(msg.value.clone()).or_default();
                add_vote(prep_list, &sender_pk);
            }
            MessageType::Commit | MessageType::Externalize => {
                let nom_list = state.nominations.entry(msg.value.clone()).or_default();
                add_vote(nom_list, &sender_pk);
                let prep_list = state.prepare_votes.entry(msg.value.clone()).or_default();
                add_vote(prep_list, &sender_pk);
                let com_list = state.commit_votes.entry(msg.value.clone()).or_default();
                add_vote(com_list, &sender_pk);
            }
        }

        let new_phase = self.check_state_transitions(msg.slot, &msg.value);

        if new_phase != initial_phase {
            let reply_type = match new_phase {
                Phase::Prepare => Some(MessageType::Prepare),
                Phase::Commit => Some(MessageType::Commit),
                Phase::Externalized => Some(MessageType::Externalize),
                _ => None,
            };

            if let Some(t) = reply_type {
                return Ok(Some(ConsensusMessage::new(
                    msg.slot,
                    self.node_id.clone(),
                    t,
                    msg.value,
                )));
            }
        }

        Ok(None)
    }

    fn check_state_transitions(&mut self, slot: u64, value: &str) -> Phase {
        let Some(state) = self.slot_states.get_mut(&slot) else {
            return Phase::Open;
        };
        if state.phase == Phase::Externalized {
            return Phase::Externalized;
        }

        let is_validator = self
            .quorum_set
            .validators
            .iter()
            .any(|v| v.as_ref() == self.node_pk.as_ref());

        if let Some(nodes) = state.nominations.get(value) {
            if self.quorum_set.is_quorum_slice(nodes) {
                if state.phase == Phase::Open || state.phase == Phase::Nominate {
                    state.phase = Phase::Prepare;
                }
                if is_validator {
                    let voters = state.prepare_votes.entry(value.to_string()).or_default();
                    add_vote(voters, &self.node_pk);
                }
            }
        }

        if let Some(nodes) = state.prepare_votes.get(value) {
            if self.quorum_set.is_quorum_slice(nodes) {
                if state.phase != Phase::Externalized {
                    state.phase = Phase::Commit;
                }
                if is_validator {
                    let voters = state.commit_votes.entry(value.to_string()).or_default();
                    add_vote(voters, &self.node_pk);
                }
            }
        }

        if let Some(nodes) = state.commit_votes.get(value) {
            if self.quorum_set.is_quorum_slice(nodes) {
                state.phase = Phase::Externalized;
                state.externalized_value = Some(value.to_string());
            }
        }

        state.phase
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::Wallet;

    #[test]
    fn test_consensus_message_signing_and_verification() {
        let wallet = Wallet::new();
        let mut msg = ConsensusMessage::new(
            1,
            wallet.public_key_hex(),
            MessageType::Nominate,
            "block_hash_123".to_string(),
        );

        // Before signing, signature is None and verify returns false
        assert!(!msg.verify_signature());

        msg.sign(&wallet);
        assert!(msg.signature.is_some());
        assert!(msg.verify_signature());

        // Tampering with slot
        let mut tampered_slot = msg.clone();
        tampered_slot.slot = 2;
        assert!(!tampered_slot.verify_signature());

        // Tampering with value
        let mut tampered_val = msg.clone();
        tampered_val.value = "different_hash".to_string();
        assert!(!tampered_val.verify_signature());

        // Tampering with msg_type
        let mut tampered_type = msg.clone();
        tampered_type.msg_type = MessageType::Commit;
        assert!(!tampered_type.verify_signature());
    }

    #[test]
    fn test_consensus_message_rkyv_roundtrip() {
        let wallet = Wallet::new();
        let mut msg = ConsensusMessage::new(
            5,
            wallet.public_key_hex(),
            MessageType::Prepare,
            "val_test".to_string(),
        );
        msg.sign(&wallet);

        let bytes = msg.to_bytes().expect("Serialization should succeed");
        let decoded = ConsensusMessage::from_bytes(&bytes).expect("Deserialization should succeed");

        assert_eq!(msg, decoded);
        assert!(decoded.verify_signature());
    }

    #[test]
    fn test_single_validator_nomination_reaches_externalized() {
        let wallet = Wallet::new();
        let qset = QuorumSet::new(1, vec![wallet.public_key.clone()]);
        let mut consensus = Consensus::new(wallet.public_key_hex(), qset, 1);

        let result = consensus.nominate(1, "genesis_next_hash".to_string());
        assert!(result.is_ok());

        assert!(consensus.is_slot_externalized(1));
        assert_eq!(
            consensus.get_externalized_value(1),
            Some("genesis_next_hash")
        );
    }

    #[test]
    fn test_multi_validator_consensus_flow() {
        let w_a = Wallet::new();
        let w_b = Wallet::new();
        let w_c = Wallet::new();

        let validators = vec![
            w_a.public_key.clone(),
            w_b.public_key.clone(),
            w_c.public_key.clone(),
        ];
        // 2-of-3 threshold
        let qset_a = QuorumSet::new(2, validators.clone());
        let qset_b = QuorumSet::new(2, validators.clone());

        let mut node_a = Consensus::new(w_a.public_key_hex(), qset_a, 1);
        let mut node_b = Consensus::new(w_b.public_key_hex(), qset_b, 1);

        let candidate_value = "block_hash_abc123".to_string();

        // 1. Node A nominates
        let mut nom_a = node_a.nominate(1, candidate_value.clone()).unwrap();
        nom_a.sign(&w_a);
        // Quorum is 2, node A alone is not externalized yet (remains in Nominate)
        assert_eq!(node_a.get_slot_state(1).unwrap().phase, Phase::Nominate);

        // 2. Node B nominates candidate_value
        let mut nom_b = node_b.nominate(1, candidate_value.clone()).unwrap();
        nom_b.sign(&w_b);

        // 3. Node A receives Node B's nomination message
        let reply_a = node_a.process_message(nom_b).unwrap();
        // Quorum threshold (2) for nomination is reached on A -> transitions to Prepare!
        assert_eq!(node_a.get_slot_state(1).unwrap().phase, Phase::Prepare);
        assert!(reply_a.is_some());
        let mut prep_msg_a = reply_a.unwrap();
        assert_eq!(prep_msg_a.msg_type, MessageType::Prepare);
        prep_msg_a.sign(&w_a);

        // 4. Node B receives Node A's nomination message
        let reply_b = node_b.process_message(nom_a).unwrap();
        assert_eq!(node_b.get_slot_state(1).unwrap().phase, Phase::Prepare);
        assert!(reply_b.is_some());
        let mut prep_msg_b = reply_b.unwrap();
        assert_eq!(prep_msg_b.msg_type, MessageType::Prepare);
        prep_msg_b.sign(&w_b);

        // 5. Node A processes Node B's Prepare message -> transitions to Commit
        let reply_a_commit = node_a.process_message(prep_msg_b).unwrap();
        assert_eq!(node_a.get_slot_state(1).unwrap().phase, Phase::Commit);
        assert!(reply_a_commit.is_some());
        let mut com_msg_a = reply_a_commit.unwrap();
        assert_eq!(com_msg_a.msg_type, MessageType::Commit);
        com_msg_a.sign(&w_a);

        // 6. Node B processes Node A's Prepare message -> transitions to Commit
        let reply_b_commit = node_b.process_message(prep_msg_a).unwrap();
        assert_eq!(node_b.get_slot_state(1).unwrap().phase, Phase::Commit);
        let mut com_msg_b = reply_b_commit.unwrap();
        com_msg_b.sign(&w_b);

        // 7. Node A processes Node B's Commit message -> transitions to Externalized!
        let ext_reply = node_a.process_message(com_msg_b).unwrap();
        assert!(node_a.is_slot_externalized(1));
        assert_eq!(
            node_a.get_externalized_value(1),
            Some(candidate_value.as_str())
        );
        assert!(ext_reply.is_some());
        assert_eq!(ext_reply.unwrap().msg_type, MessageType::Externalize);
    }

    #[test]
    fn test_invalid_signature_rejected() {
        let w_a = Wallet::new();
        let w_b = Wallet::new();
        let qset = QuorumSet::new(1, vec![w_a.public_key.clone()]);
        let mut consensus = Consensus::new(w_a.public_key_hex(), qset, 1);

        let mut msg = ConsensusMessage::new(
            1,
            w_b.public_key_hex(),
            MessageType::Nominate,
            "fake_val".to_string(),
        );
        // Sign with a different wallet so signature doesn't match sender_id
        msg.sign(&w_a);

        let result = consensus.process_message(msg);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Invalid cryptographic signature"));
    }

    #[test]
    fn test_non_validator_vote_ignored() {
        let w_val = Wallet::new();
        let w_non_val = Wallet::new();
        // Only w_val is in quorum set with threshold 1
        let qset = QuorumSet::new(1, vec![w_val.public_key.clone()]);
        let mut consensus = Consensus::new(w_val.public_key_hex(), qset, 1);

        let mut msg = ConsensusMessage::new(
            1,
            w_non_val.public_key_hex(),
            MessageType::Nominate,
            "non_val_candidate".to_string(),
        );
        msg.sign(&w_non_val);

        let result = consensus.process_message(msg).unwrap();
        assert!(result.is_none());
        assert_eq!(consensus.get_slot_state(1).unwrap().phase, Phase::Open);
        assert!(!consensus.is_slot_externalized(1));
    }
}