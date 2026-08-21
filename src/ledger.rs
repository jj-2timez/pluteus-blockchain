use pqc_combo::DilithiumPublicKey;
use rkyv::{Archive, Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::{
    consensus::{Consensus, ConsensusMessage, QuorumSet},
    extrinsic::{Context, Extrinsic},
    programs::{ProgramResult, ProgramTransformer, StateChange},
    wallet::Wallet,
};

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub struct Block {
    pub transactions: Vec<Extrinsic>,
    pub previous_hash: String,
    pub signer: String,
    pub block_height: u64,
    pub timestamp: u64,
    pub signature: String,
}

impl Block {
    /// Hashes the block data sequentially using Blake3.
    pub fn hash_data(&self) -> blake3::Hash {
        let mut hasher = blake3::Hasher::new();

        // 1. Process the vector of transactions by folding their individual hashes
        for tx in &self.transactions {
            hasher.update(tx.hash_data().as_bytes());
        }

        // 2. Hash standard header metadata fields safely via reference
        hasher.update(self.previous_hash.as_bytes());
        hasher.update(self.signer.as_bytes());
        hasher.update(&self.block_height.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());

        hasher.finalize()
    }
}

#[derive(Default, Clone)]
pub struct Accounts {
    accounts: Vec<DilithiumPublicKey>,
    balances: BTreeMap<String, u64>,
}

impl Accounts {
    pub fn new() -> Self {
        Self {
            accounts: Vec::new(),
            balances: BTreeMap::new(),
        }
    }

    /// Helper to convert a Public Key to a hex string address.
    fn to_address(public_key: &DilithiumPublicKey) -> String {
        hex::encode(public_key.as_ref())
    }

    /// Helper to safely append a key to the accounts vector if it doesn't exist.
    fn ensure_account_exists(&mut self, public_key: &DilithiumPublicKey) {
        let exists = self
            .accounts
            .iter()
            .any(|pk| pk.as_ref() == public_key.as_ref());

        if !exists {
            self.accounts.push(public_key.clone());
        }
    }

    /// Adds a new account and initializes its balance to 0 if not present.
    pub fn add_account(&mut self, public_key: &DilithiumPublicKey) {
        self.ensure_account_exists(public_key);
        let address = Self::to_address(public_key);
        self.balances.entry(address).or_insert(0);
    }

    /// Adds or initializes an account by hex address.
    pub fn add_account_address(&mut self, address: impl Into<String>) {
        self.balances.entry(address.into()).or_insert(0);
    }

    /// Retrieves the balance for a given public key.
    pub fn get_balance(&mut self, public_key: &DilithiumPublicKey) -> u64 {
        self.ensure_account_exists(public_key);
        let address = Self::to_address(public_key);
        self.get_balance_by_address(&address)
    }

    /// Retrieves the balance for a given hex address.
    pub fn get_balance_by_address(&self, address: &str) -> u64 {
        *self.balances.get(address).unwrap_or(&0)
    }

    /// Credits (adds) a strictly positive u64 amount to the public key's balance.
    pub fn credit_balance(&mut self, public_key: &DilithiumPublicKey, amount: u64) {
        self.ensure_account_exists(public_key);
        let address = Self::to_address(public_key);
        self.credit_balance_by_address(&address, amount);
    }

    /// Credits a u64 amount to an account balance by hex address.
    pub fn credit_balance_by_address(&mut self, address: &str, amount: u64) {
        let current_balance = *self.balances.get(address).unwrap_or(&0);
        self.balances
            .insert(address.to_string(), current_balance.saturating_add(amount));
    }

    /// Debits (subtracts) a strictly positive u64 amount from the public key's balance.
    /// Returns true if successful, false if there are insufficient funds.
    pub fn debit_balance(&mut self, public_key: &DilithiumPublicKey, amount: u64) -> bool {
        self.ensure_account_exists(public_key);
        let address = Self::to_address(public_key);
        self.debit_balance_by_address(&address, amount)
    }

    /// Debits a u64 amount from an account balance by hex address.
    pub fn debit_balance_by_address(&mut self, address: &str, amount: u64) -> bool {
        let current_balance = *self.balances.get(address).unwrap_or(&0);

        if current_balance >= amount {
            self.balances.insert(address.to_string(), current_balance - amount);
            true
        } else {
            false
        }
    }
}

pub struct Ledger {
    pub blocks: Vec<Block>,
    pub accounts: Accounts,
    pub consensus: Consensus,
    pub programs: BTreeMap<uuid::Uuid, String>,
}

impl Ledger {
    /// Initializes a Ledger with specified node ID, quorum set, and initial consensus slot.
    pub fn new(node_id: String, quorum_set: QuorumSet, initial_slot: u64) -> Self {
        Self {
            blocks: Vec::new(),
            accounts: Accounts::new(),
            consensus: Consensus::new(node_id, quorum_set, initial_slot),
            programs: BTreeMap::new(),
        }
    }

    /// Initializes Ledger with a Genesis block signed by a given wallet and a QuorumSet.
    pub fn new_with_genesis_signer(genesis_signer: &Wallet, quorum_set: QuorumSet) -> Self {
        let genesis_block = genesis_signer.new_block(
            vec![],        // Empty transactions
            String::new(), // Empty previous hash
            0,             // Block height 0
        );

        let node_id = genesis_signer.public_key_hex();
        Self {
            blocks: vec![genesis_block],
            accounts: Accounts::new(),
            consensus: Consensus::new(node_id, quorum_set, 1),
            programs: BTreeMap::new(),
        }
    }

    /// Initializes Ledger with a specific Genesis block.
    pub fn new_with_genesis_block(
        genesis_block: Block,
        node_id: String,
        quorum_set: QuorumSet,
    ) -> Self {
        let next_slot = genesis_block.block_height + 1;
        Self {
            blocks: vec![genesis_block],
            accounts: Accounts::new(),
            consensus: Consensus::new(node_id, quorum_set, next_slot),
            programs: BTreeMap::new(),
        }
    }

    /// Appends a block to the chain and starts the next slot in consensus.
    pub fn add_block(&mut self, block: Block) -> Result<(), String> {
        if !self.is_block_height_valid(&block) {
            let expected = self.blocks.last().map(|b| b.block_height + 1).unwrap_or(0);
            return Err(format!(
                "Invalid block height: expected {}, got {}",
                expected, block.block_height
            ));
        }

        if !self.is_previous_hash_valid(&block) {
            let expected = self
                .blocks
                .last()
                .map(|b| b.hash_data().to_string())
                .unwrap_or_default();

            return Err(format!(
                "Invalid previous block hash: expected {}, got {}",
                expected, block.previous_hash
            ));
        }

        let next_slot = block.block_height + 1;
        self.blocks.push(block);
        self.consensus.start_slot(next_slot);
        Ok(())
    }

    /// Deploys a program script under a specific Uuid into the ledger's BTreeMap state.
    pub fn deploy_program(&mut self, program_id: uuid::Uuid, script: String) -> Result<(), String> {
        if script.trim().is_empty() {
            return Err("Program script cannot be empty".to_string());
        }
        self.programs.insert(program_id, script);
        Ok(())
    }

    /// Deploys a script to the ledger, automatically generating a new Uuid.
    pub fn deploy_script(&mut self, script: String) -> Result<uuid::Uuid, String> {
        let program_id = uuid::Uuid::new_v4();
        self.deploy_program(program_id, script)?;
        Ok(program_id)
    }

    /// Retrieves a deployed program script by its Uuid.
    pub fn get_program(&self, program_id: &uuid::Uuid) -> Option<&String> {
        self.programs.get(program_id)
    }

    /// Alias for get_program to retrieve a deployed script from the ledger.
    pub fn get_script(&self, script_id: &uuid::Uuid) -> Option<&String> {
        self.get_program(script_id)
    }

    /// Executes a smart contract (registered by Uuid or as raw Starlark script),
    /// deserializes the zero-copy rkyv result, and applies resulting state changes.
    pub fn execute_program(
        &mut self,
        script_or_program_id: &str,
        sender_id: &str,
        payload: &str,
    ) -> Result<ProgramResult, String> {
        let script = if let Ok(uuid) = uuid::Uuid::parse_str(script_or_program_id) {
            if let Some(stored) = self.programs.get(&uuid) {
                stored.as_str()
            } else {
                script_or_program_id
            }
        } else {
            script_or_program_id
        };

        let result_bytes = ProgramTransformer::execute_program(script, sender_id, payload)?;
        let program_result = ProgramResult::from_bytes(&result_bytes)
            .map_err(|e| format!("Failed to deserialize ProgramResult: {}", e))?;

        if program_result.status != "success" && program_result.status != "ok" {
            return Err(format!(
                "Program execution failed with status: {}",
                program_result.status
            ));
        }

        self.apply_state_changes(sender_id, &program_result.state_changes)?;
        Ok(program_result)
    }

    /// Applies state changes resulting from program execution to the accounts.
    pub fn apply_state_changes(
        &mut self,
        caller_id: &str,
        changes: &[StateChange],
    ) -> Result<(), String> {
        for change in changes {
            match change.action.to_lowercase().as_str() {
                "transfer" => {
                    if change.amount > 0 {
                        if !self.accounts.debit_balance_by_address(caller_id, change.amount) {
                            return Err(format!(
                                "Contract state change failed: insufficient funds for caller {} to transfer {}",
                                caller_id, change.amount
                            ));
                        }
                        self.accounts.credit_balance_by_address(&change.to_address, change.amount);
                    }
                }
                "credit" | "mint" => {
                    if change.amount > 0 {
                        self.accounts.credit_balance_by_address(&change.to_address, change.amount);
                    }
                }
                "debit" | "burn" => {
                    if change.amount > 0 {
                        if !self.accounts.debit_balance_by_address(&change.to_address, change.amount) {
                            return Err(format!(
                                "Contract state change failed: insufficient funds for {} to debit {}",
                                change.to_address, change.amount
                            ));
                        }
                    }
                }
                _ => {
                    // Custom action tag
                }
            }
        }
        Ok(())
    }

    /// Nominates a block's hash in consensus for the block's height slot.
    pub fn nominate_block(&mut self, block: &Block) -> Result<ConsensusMessage, String> {
        let block_hash = block.hash_data().to_string();
        self.consensus.nominate(block.block_height, block_hash)
    }

    /// Finalizes and adds a block only if consensus has externalized for this slot with matching block hash.
    pub fn finalize_consensus_block(&mut self, block: Block) -> Result<(), String> {
        let slot = block.block_height;
        let ext_val = self
            .consensus
            .get_externalized_value(slot)
            .ok_or_else(|| format!("Slot {} has not reached consensus (not externalized)", slot))?;

        let block_hash = block.hash_data().to_string();
        if ext_val != block_hash {
            return Err(format!(
                "Consensus externalized value {} does not match block hash {}",
                ext_val, block_hash
            ));
        }

        self.add_block(block)
    }

    /// Validates if the entire block height sequence in the ledger is valid (0, 1, 2, ...).
    pub fn is_ledger_height_valid(&self) -> bool {
        for (index, block) in self.blocks.iter().enumerate() {
            if block.block_height != index as u64 {
                return false;
            }
        }
        true
    }

    /// Validates if a proposed candidate block has a valid block height relative to the ledger.
    pub fn is_block_height_valid(&self, block: &Block) -> bool {
        match self.blocks.last() {
            None => block.block_height == 0,
            Some(last_block) => block.block_height == last_block.block_height + 1,
        }
    }

    /// Validates if the entire hash chain in the ledger is valid.
    pub fn is_ledger_hash_chain_valid(&self) -> bool {
        if self.blocks.is_empty() {
            return true;
        }
        if !self.blocks[0].previous_hash.is_empty() {
            return false;
        }
        for i in 1..self.blocks.len() {
            let prev_hash_calculated = self.blocks[i - 1].hash_data().to_string();
            if self.blocks[i].previous_hash != prev_hash_calculated {
                return false;
            }
        }
        true
    }

    /// Validates if a proposed candidate block has a valid previous block hash relative to the ledger.
    pub fn is_previous_hash_valid(&self, block: &Block) -> bool {
        match self.blocks.last() {
            None => block.previous_hash.is_empty(),
            Some(last_block) => block.previous_hash == last_block.hash_data().to_string(),
        }
    }

    // --- Extrinsic Processing ---

    /// Checks which extrinsics are covered by the sender's account balance
    /// (without mutating the actual ledger state).
    pub fn get_covered_extrinsics(&self, extrinsics: &[Extrinsic]) -> Vec<Extrinsic> {
        let mut temp_balances = self.accounts.balances.clone();
        let mut covered = Vec::new();

        for tx in extrinsics {
            if tx.transaction_context == Context::ExchangeAssets {
                covered.push(tx.clone());
                continue;
            }

            let sender = &tx.sender_public_key;
            let amount = tx.amount;
            let current_balance = *temp_balances.get(sender).unwrap_or(&0);

            if current_balance >= amount {
                temp_balances.insert(sender.clone(), current_balance - amount);
                covered.push(tx.clone());
            }
        }

        covered
    }

    /// Checks if a single extrinsic is covered by the sender's account balance.
    pub fn is_extrinsic_covered(&self, extrinsic: &Extrinsic) -> bool {
        let single_slice = std::slice::from_ref(extrinsic);
        !self.get_covered_extrinsics(single_slice).is_empty()
    }

    /// Applies the transactions to the ledger's account balances and contract states.
    /// Returns a String error message if an operation fails.
    pub fn push_extrinsics(&mut self, extrinsics: &[Extrinsic]) -> Result<(), String> {
        for tx in extrinsics {
            match tx.transaction_context {
                Context::ExchangeAssets => {
                    // Exchange context
                }
                Context::TransferAssets => {
                    let amount = tx.amount;
                    let debit_success = self.accounts.debit_balance_by_address(&tx.sender_public_key, amount);
                    if !debit_success {
                        return Err(format!(
                            "Insufficient funds for address: {}",
                            tx.sender_public_key
                        ));
                    }
                    self.accounts.credit_balance_by_address(&tx.receiver_public_key, amount);
                }
                Context::DeployProgram => {
                    let script = tx.payload.as_deref().ok_or_else(|| {
                        "DeployProgram extrinsic missing payload script".to_string()
                    })?;
                    let program_id = uuid::Uuid::parse_str(&tx.receiver_public_key).unwrap_or(tx.id);

                    if tx.amount > 0 {
                        if !self.accounts.debit_balance_by_address(&tx.sender_public_key, tx.amount) {
                            return Err(format!(
                                "Insufficient funds for address: {}",
                                tx.sender_public_key
                            ));
                        }
                        self.accounts.credit_balance_by_address(&program_id.to_string(), tx.amount);
                    }

                    self.deploy_program(program_id, script.to_string())?;
                }
                Context::ExecuteProgram => {
                    let payload = tx.payload.as_deref().unwrap_or("");

                    if tx.amount > 0 {
                        if !self.accounts.debit_balance_by_address(&tx.sender_public_key, tx.amount) {
                            return Err(format!(
                                "Insufficient funds for address: {}",
                                tx.sender_public_key
                            ));
                        }
                        self.accounts.credit_balance_by_address(&tx.receiver_public_key, tx.amount);
                    }

                    self.execute_program(
                        &tx.receiver_public_key,
                        &tx.sender_public_key,
                        payload,
                    )?;
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{extrinsic::Context, wallet::Wallet};

    fn test_quorum_set(signer: &Wallet) -> QuorumSet {
        QuorumSet::new(1, vec![signer.public_key.clone()])
    }

    #[test]
    fn test_ledger_initialization_empty() {
        let signer = Wallet::new();
        let qset = test_quorum_set(&signer);
        let ledger = Ledger::new(signer.public_key_hex(), qset, 0);
        assert!(ledger.blocks.is_empty());
        assert!(ledger.accounts.balances.is_empty());
        assert_eq!(ledger.consensus.current_slot, 0);
    }

    #[test]
    fn test_ledger_initialization_with_genesis_signer() {
        let signer = Wallet::new();
        let qset = test_quorum_set(&signer);
        let ledger = Ledger::new_with_genesis_signer(&signer, qset);

        assert_eq!(ledger.blocks.len(), 1);
        assert_eq!(ledger.blocks[0].block_height, 0);
        assert!(ledger.blocks[0].previous_hash.is_empty());
        assert_eq!(ledger.blocks[0].signer, signer.public_key_hex());
        assert_eq!(ledger.consensus.current_slot, 1);
    }

    #[test]
    fn test_add_valid_block() {
        let signer = Wallet::new();
        let qset = test_quorum_set(&signer);
        let mut ledger = Ledger::new_with_genesis_signer(&signer, qset);

        let genesis_hash = ledger.blocks[0].hash_data().to_string();

        // Create a valid second block (height 1, pointing to genesis hash)
        let next_block = signer.new_block(vec![], genesis_hash, 1);

        let result = ledger.add_block(next_block);
        assert!(result.is_ok());
        assert_eq!(ledger.blocks.len(), 2);
        assert_eq!(ledger.consensus.current_slot, 2);
    }

    #[test]
    fn test_add_block_invalid_height() {
        let signer = Wallet::new();
        let qset = test_quorum_set(&signer);
        let mut ledger = Ledger::new_with_genesis_signer(&signer, qset);

        let genesis_hash = ledger.blocks[0].hash_data().to_string();

        // Invalid height: expected 1, providing 5
        let bad_block = signer.new_block(vec![], genesis_hash, 5);

        let result = ledger.add_block(bad_block);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid block height"));
    }

    #[test]
    fn test_add_block_invalid_previous_hash() {
        let signer = Wallet::new();
        let qset = test_quorum_set(&signer);
        let mut ledger = Ledger::new_with_genesis_signer(&signer, qset);

        // Invalid previous hash: providing a fake string instead of actual genesis hash
        let bad_block = signer.new_block(vec![], "fake_previous_hash".to_string(), 1);

        let result = ledger.add_block(bad_block);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid previous block hash"));
    }

    #[test]
    fn test_get_covered_extrinsics() {
        let signer = Wallet::new();
        let qset = test_quorum_set(&signer);
        let mut ledger = Ledger::new(signer.public_key_hex(), qset, 0);
        let sender = Wallet::new();
        let receiver = Wallet::new();

        // Mint some initial balance to the sender directly inside ledger accounts
        ledger.accounts.credit_balance(&sender.public_key, 100);

        // Transaction 1: Valid (wants 40, has 100)
        let tx1 = sender.new_extrinsic(receiver.public_key_hex(), 40, Context::TransferAssets);
        // Transaction 2: Valid (wants 50, remaining balance is 60)
        let tx2 = sender.new_extrinsic(receiver.public_key_hex(), 50, Context::TransferAssets);
        // Transaction 3: Invalid (wants 20, remaining balance is only 10)
        let tx3 = sender.new_extrinsic(receiver.public_key_hex(), 20, Context::TransferAssets);

        let txs = vec![tx1.clone(), tx2.clone(), tx3.clone()];
        let covered = ledger.get_covered_extrinsics(&txs);

        // Only tx1 and tx2 should be covered
        assert_eq!(covered.len(), 2);
        assert_eq!(covered[0].id, tx1.id);
        assert_eq!(covered[1].id, tx2.id);

        // Ensure the actual ledger balance wasn't mutated during simulation
        assert_eq!(ledger.accounts.get_balance(&sender.public_key), 100);
    }

    #[test]
    fn test_is_extrinsic_covered() {
        let signer = Wallet::new();
        let qset = test_quorum_set(&signer);
        let mut ledger = Ledger::new(signer.public_key_hex(), qset, 0);
        let sender = Wallet::new();
        let receiver = Wallet::new();

        ledger.accounts.credit_balance(&sender.public_key, 50);

        let valid_tx = sender.new_extrinsic(receiver.public_key_hex(), 30, Context::TransferAssets);
        let invalid_tx = sender.new_extrinsic(receiver.public_key_hex(), 60, Context::TransferAssets);

        assert!(ledger.is_extrinsic_covered(&valid_tx));
        assert!(!ledger.is_extrinsic_covered(&invalid_tx));
    }

    #[test]
    fn test_push_extrinsics_success() {
        let signer = Wallet::new();
        let qset = test_quorum_set(&signer);
        let mut ledger = Ledger::new(signer.public_key_hex(), qset, 0);
        let sender = Wallet::new();
        let receiver = Wallet::new();

        // Setup base balance
        ledger.accounts.credit_balance(&sender.public_key, 100);
        ledger.accounts.add_account(&receiver.public_key);

        let tx = sender.new_extrinsic(receiver.public_key_hex(), 40, Context::TransferAssets);

        // Execute state modification
        let result = ledger.push_extrinsics(&[tx]);
        assert!(result.is_ok());

        // Balances must be mutated permanently
        assert_eq!(ledger.accounts.get_balance(&sender.public_key), 60);
        assert_eq!(ledger.accounts.get_balance(&receiver.public_key), 40);
    }

    #[test]
    fn test_push_extrinsics_insufficient_funds() {
        let signer = Wallet::new();
        let qset = test_quorum_set(&signer);
        let mut ledger = Ledger::new(signer.public_key_hex(), qset, 0);
        let sender = Wallet::new();
        let receiver = Wallet::new();

        ledger.accounts.credit_balance(&sender.public_key, 10);

        let tx = sender.new_extrinsic(receiver.public_key_hex(), 50, Context::TransferAssets);

        let result = ledger.push_extrinsics(&[tx]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Insufficient funds"));

        // Balances must remain unchanged on failure
        assert_eq!(ledger.accounts.get_balance(&sender.public_key), 10);
    }

    #[test]
    fn test_chain_validation_helpers() {
        let signer = Wallet::new();
        let qset = test_quorum_set(&signer);
        let mut ledger = Ledger::new_with_genesis_signer(&signer, qset);

        assert!(ledger.is_ledger_height_valid());
        assert!(ledger.is_ledger_hash_chain_valid());

        // Push valid block
        let genesis_hash = ledger.blocks[0].hash_data().to_string();
        let block1 = signer.new_block(vec![], genesis_hash, 1);
        ledger.add_block(block1).unwrap();

        assert!(ledger.is_ledger_height_valid());
        assert!(ledger.is_ledger_hash_chain_valid());
    }

    #[test]
    fn test_finalize_consensus_block() {
        let signer = Wallet::new();
        let qset = test_quorum_set(&signer);
        let mut ledger = Ledger::new_with_genesis_signer(&signer, qset);

        let genesis_hash = ledger.blocks[0].hash_data().to_string();
        let block1 = signer.new_block(vec![], genesis_hash, 1);
        let block1_hash = block1.hash_data().to_string();

        // 1. Attempt finalizing before consensus -> error
        let err = ledger.finalize_consensus_block(block1.clone());
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("not reached consensus"));

        // 2. Nominate block hash in consensus (single validator -> reaches Externalized)
        let nom_msg = ledger.nominate_block(&block1).unwrap();
        assert_eq!(nom_msg.value, block1_hash);
        assert!(ledger.consensus.is_slot_externalized(1));

        // 3. Finalize now succeeds and block is added to ledger
        let res = ledger.finalize_consensus_block(block1.clone());
        assert!(res.is_ok());
        assert_eq!(ledger.blocks.len(), 2);
        assert_eq!(ledger.blocks[1].hash_data().to_string(), block1_hash);
        assert_eq!(ledger.consensus.current_slot, 2);
    }

    #[test]
    fn test_ledger_deploy_and_get_program() {
        let signer = Wallet::new();
        let qset = test_quorum_set(&signer);
        let mut ledger = Ledger::new(signer.public_key_hex(), qset, 0);

        let script = r#"
def execute(sender, payload):
    return {
        "status": "success",
        "state_changes": []
    }
"#;
        let prog_id = uuid::Uuid::new_v4();
        assert!(ledger.get_program(&prog_id).is_none());
        ledger
            .deploy_program(prog_id, script.to_string())
            .unwrap();

        assert_eq!(
            ledger.get_program(&prog_id),
            Some(&script.to_string())
        );
    }

    #[test]
    fn test_ledger_execute_program_state_changes() {
        let signer = Wallet::new();
        let qset = test_quorum_set(&signer);
        let mut ledger = Ledger::new(signer.public_key_hex(), qset, 0);
        let alice = Wallet::new();
        let bob = Wallet::new();

        ledger.accounts.credit_balance(&alice.public_key, 100);

        let script = r#"
def execute(sender, payload):
    return {
        "status": "success",
        "state_changes": [
            {
                "action": "transfer",
                "to_address": payload,
                "amount": 35,
            }
        ]
    }
"#;
        let prog_id = uuid::Uuid::new_v4();
        ledger
            .deploy_program(prog_id, script.to_string())
            .unwrap();

        let result = ledger.execute_program(
            &prog_id.to_string(),
            &alice.public_key_hex(),
            &bob.public_key_hex(),
        );

        assert!(result.is_ok());
        let pr = result.unwrap();
        assert_eq!(pr.status, "success");
        assert_eq!(ledger.accounts.get_balance(&alice.public_key), 65);
        assert_eq!(ledger.accounts.get_balance(&bob.public_key), 35);
    }

    #[test]
    fn test_ledger_push_extrinsics_deploy_and_execute_program() {
        let signer = Wallet::new();
        let qset = test_quorum_set(&signer);
        let mut ledger = Ledger::new(signer.public_key_hex(), qset, 0);
        let creator = Wallet::new();
        let user = Wallet::new();
        let recipient = Wallet::new();

        ledger.accounts.credit_balance(&creator.public_key, 1000);
        ledger.accounts.credit_balance(&user.public_key, 500);

        let contract_id = uuid::Uuid::new_v4();
        let contract_script = r#"
def execute(sender, payload):
    return {
        "status": "success",
        "state_changes": [
            {
                "action": "credit",
                "to_address": sender,
                "amount": 50,
            },
            {
                "action": "transfer",
                "to_address": payload,
                "amount": 20,
            }
        ]
    }
"#;

        // 1. Deploy program via DeployProgram extrinsic
        let deploy_tx = creator.new_program_extrinsic(
            contract_id.to_string(),
            0,
            Context::DeployProgram,
            Some(contract_script.to_string()),
        );

        // 2. Execute program via ExecuteProgram extrinsic
        let exec_tx = user.new_program_extrinsic(
            contract_id.to_string(),
            0,
            Context::ExecuteProgram,
            Some(recipient.public_key_hex()),
        );

        let push_res = ledger.push_extrinsics(&[deploy_tx, exec_tx]);
        assert!(push_res.is_ok());

        assert!(ledger.get_program(&contract_id).is_some());
        // User had 500, received 50 mint credit, transferred 20 -> 530
        assert_eq!(ledger.accounts.get_balance(&user.public_key), 530);
        // Recipient received 20
        assert_eq!(ledger.accounts.get_balance(&recipient.public_key), 20);
    }

    #[test]
    fn test_ledger_program_insufficient_funds_fails() {
        let signer = Wallet::new();
        let qset = test_quorum_set(&signer);
        let mut ledger = Ledger::new(signer.public_key_hex(), qset, 0);
        let user = Wallet::new();
        let recipient = Wallet::new();

        ledger.accounts.credit_balance(&user.public_key, 10);

        let script = r#"
def execute(sender, payload):
    return {
        "status": "success",
        "state_changes": [
            {
                "action": "transfer",
                "to_address": payload,
                "amount": 100,
            }
        ]
    }
"#;
        let result = ledger.execute_program(script, &user.public_key_hex(), &recipient.public_key_hex());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("insufficient funds"));
        // Balance unchanged
        assert_eq!(ledger.accounts.get_balance(&user.public_key), 10);
    }
}
