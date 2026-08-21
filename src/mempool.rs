use crate::extrinsic::Extrinsic;
use std::collections::HashSet;

#[derive(Debug, Default)]
pub struct MemPool {
    pub transaction_pool: HashSet<Extrinsic>,
}

impl MemPool {
    pub fn new() -> Self {
        Self {
            transaction_pool: HashSet::new(),
        }
    }
    pub fn add_extrinsic(&mut self, tx: Extrinsic) {
        self.transaction_pool.insert(tx);
    }
    pub fn push(&mut self, tx: Extrinsic) {
        self.add_extrinsic(tx);
    }
    pub fn contains(&self, tx: &Extrinsic) -> bool {
        self.transaction_pool.contains(tx)
    }
    pub fn pop_extrinsic(&mut self, new_block_transactions: &[Extrinsic]) {
        // Build a temporary set of items to remove for instant O(1) lookups
        let to_remove: HashSet<&Extrinsic> = new_block_transactions.iter().collect();
        // Retain only the transactions that were NOT included in the new block
        self.transaction_pool.retain(|tx| !to_remove.contains(tx));
    }
    pub fn remove_batch(&mut self, new_block_transactions: &[Extrinsic]) {
        self.pop_extrinsic(new_block_transactions);
    }
    pub fn len(&self) -> usize {
        self.transaction_pool.len()
    }
    pub fn is_empty(&self) -> bool {
        self.transaction_pool.is_empty()
    }
}