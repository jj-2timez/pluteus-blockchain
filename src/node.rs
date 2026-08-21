use async_trait::async_trait;
use rings_core::dht::Did;
use rings_core::ecc::SecretKey;
use rings_core::message::{CustomMessage, Message, MessagePayload, MessageVerificationExt};
use rings_core::session::SessionSk;
use rings_core::storage::MemStorage;
use rings_core::swarm::callback::{SwarmCallback, SwarmEvent};
use rings_core::swarm::{Swarm, SwarmBuilder};
use rings_transport::core::transport::WebrtcConnectionState;
use rkyv::{Archive, Deserialize, Serialize};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use crate::{
    consensus::{ConsensusMessage, QuorumSet},
    extrinsic::Extrinsic,
    ledger::{Block, Ledger},
    mempool::MemPool,
    programs::ProgramResult,
    wallet::Wallet,
};

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub enum NetworkMessage {
    BroadcastTransaction(Extrinsic),
    ProposeBlock(Block),
    ConsensusMessage(ConsensusMessage),
    RequestChainSync { current_height: u64 },
    ResponseChainSync { blocks: Vec<Block> },
}

impl NetworkMessage {
    pub fn to_bytes(&self) -> Result<rkyv::util::AlignedVec, rkyv::rancor::Error> {
        rkyv::to_bytes::<rkyv::rancor::Error>(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, rkyv::rancor::Error> {
        rkyv::from_bytes::<Self, rkyv::rancor::Error>(bytes)
    }
}

#[derive(Clone, Default)]
pub struct NodeConfig {
    pub network_id: u32,
    pub ice_servers: String,
    pub external_address: Option<String>,
    pub dht_finger_table_size: usize,
    pub quorum_set: Option<QuorumSet>,
}

impl NodeConfig {
    pub fn with_quorum_set(mut self, quorum_set: QuorumSet) -> Self {
        self.quorum_set = Some(quorum_set);
        self
    }
}

#[derive(Debug, Clone)]
pub enum NodeEvent {
    MessageReceived {
        source: Did,
        message: NetworkMessage,
    },
    PeerConnected(Did),
    PeerDisconnected(Did),
}

pub struct NodeSwarmCallback {
    event_sender: tokio::sync::mpsc::UnboundedSender<NodeEvent>,
}

impl NodeSwarmCallback {
    pub fn new(event_sender: tokio::sync::mpsc::UnboundedSender<NodeEvent>) -> Self {
        Self { event_sender }
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl SwarmCallback for NodeSwarmCallback {
    async fn on_inbound(&self, payload: &MessagePayload) -> Result<(), Box<dyn std::error::Error>> {
        let Ok(Message::CustomMessage(CustomMessage(bytes))) =
            payload.transaction.data::<Message>()
        else {
            return Ok(());
        };

        if let Ok(message) = NetworkMessage::from_bytes(&bytes) {
            let _ = self.event_sender.send(NodeEvent::MessageReceived {
                source: payload.transaction.signer(),
                message,
            });
        }
        Ok(())
    }

    async fn on_event(&self, event: &SwarmEvent) -> Result<(), Box<dyn std::error::Error>> {
        if let SwarmEvent::ConnectionStateChange { peer, state } = event {
            match state {
                WebrtcConnectionState::Connected => {
                    let _ = self.event_sender.send(NodeEvent::PeerConnected(*peer));
                }
                WebrtcConnectionState::Closed | WebrtcConnectionState::Failed => {
                    let _ = self.event_sender.send(NodeEvent::PeerDisconnected(*peer));
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// Derives a valid secp256k1 SecretKey deterministically from a public key seed
fn derive_secp256k1_from_seed(seed: &[u8]) -> SecretKey {
    let mut counter = 0u32;
    loop {
        let mut hasher = blake3::Hasher::new();
        hasher.update(seed);
        hasher.update(&counter.to_le_bytes());

        if let Ok(sk) = libsecp256k1::SecretKey::parse(hasher.finalize().as_bytes()) {
            return SecretKey::from(sk);
        }
        counter = counter.wrapping_add(1);
    }
}

pub struct Node {
    pub wallet: Wallet,
    pub ledger: Arc<Mutex<Ledger>>,
    pub mempool: Arc<Mutex<MemPool>>,
    pub swarm: Arc<Swarm>,
    pub did: Did,
    pub event_receiver: tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<NodeEvent>>,
}

impl Node {
    pub async fn new(
        wallet: Wallet,
        config: Option<NodeConfig>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let config = config.unwrap_or_else(|| NodeConfig {
            network_id: 1,
            ice_servers: "stun://stun.l.google.com:19302".to_string(),
            external_address: None,
            dht_finger_table_size: 8,
            quorum_set: None,
        });
        let quorum_set = config.quorum_set.clone().unwrap_or_else(|| {
            QuorumSet::new(1, vec![wallet.public_key.clone()])
        });
        let genesis_block =
            Ledger::new_with_genesis_signer(&wallet, quorum_set.clone()).blocks[0].clone();
        Self::new_with_genesis_block(wallet, Some(config), genesis_block).await
    }

    pub async fn new_with_genesis_block(
        wallet: Wallet,
        config: Option<NodeConfig>,
        genesis_block: Block,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let config = config.unwrap_or_else(|| NodeConfig {
            network_id: 1,
            ice_servers: "stun://stun.l.google.com:19302".to_string(),
            external_address: None,
            dht_finger_table_size: 8,
            quorum_set: None,
        });

        let quorum_set = config.quorum_set.clone().unwrap_or_else(|| {
            QuorumSet::new(1, vec![wallet.public_key.clone()])
        });

        let secret_key = derive_secp256k1_from_seed(wallet.public_key.as_ref());
        let session_sk = SessionSk::new_with_seckey(&secret_key)?;
        let did = session_sk.account_did();

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let callback = Arc::new(NodeSwarmCallback::new(tx));

        let mut swarm_builder = SwarmBuilder::new(
            config.network_id,
            &config.ice_servers,
            Box::new(MemStorage::new()),
            session_sk,
        )
        .dht_finger_table_size(config.dht_finger_table_size)
        .callback(callback);

        if let Some(ext_addr) = config.external_address {
            swarm_builder = swarm_builder.external_address(ext_addr);
        }

        let ledger = Ledger::new_with_genesis_block(
            genesis_block,
            wallet.public_key_hex(),
            quorum_set,
        );

        Ok(Self {
            wallet,
            ledger: Arc::new(Mutex::new(ledger)),
            mempool: Arc::new(Mutex::new(MemPool::new())),
            swarm: Arc::new(swarm_builder.build()),
            did,
            event_receiver: tokio::sync::Mutex::new(rx),
        })
    }

    pub fn peer_id(&self) -> String {
        self.did.to_string()
    }

    // --- Networking Commands ---

    pub async fn connect_peer(&self, peer: Did) -> Result<(), Box<dyn std::error::Error>> {
        self.swarm.connect(peer).await?;
        Ok(())
    }

    pub async fn send_to(
        &self,
        destination: Did,
        msg: &NetworkMessage,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let bytes = msg.to_bytes()?;
        let rings_msg = Message::custom(&bytes)?;
        self.swarm.send_message(rings_msg, destination).await?;
        Ok(())
    }

    /// Unified broadcast method for any NetworkMessage
    pub async fn broadcast(&self, msg: &NetworkMessage) -> Result<(), Box<dyn std::error::Error>> {
        for peer_info in self.swarm.peers() {
            if let Ok(peer_did) = Did::from_str(&peer_info.did) {
                let _ = self.send_to(peer_did, msg).await;
            }
        }
        Ok(())
    }

    pub async fn request_chain_sync(&self, peer: Did) -> Result<(), Box<dyn std::error::Error>> {
        let current_height = self.ledger.lock().unwrap().blocks.len() as u64;
        self.send_to(peer, &NetworkMessage::RequestChainSync { current_height })
            .await
    }

    /// Proposes a value for consensus at a given slot, signs the message, and broadcasts it.
    pub async fn propose_consensus_value(
        &self,
        slot: u64,
        value: String,
    ) -> Result<ConsensusMessage, Box<dyn std::error::Error>> {
        let mut msg = {
            let mut ledger = self.ledger.lock().unwrap();
            ledger.consensus.nominate(slot, value)?
        };
        msg.sign(&self.wallet);
        self.broadcast(&NetworkMessage::ConsensusMessage(msg.clone()))
            .await?;
        Ok(msg)
    }

    /// Deploys a program (smart contract) directly into the node's ledger.
    pub fn deploy_program(&self, program_id: uuid::Uuid, script: String) -> Result<(), String> {
        let mut ledger = self.ledger.lock().unwrap();
        ledger.deploy_program(program_id, script)
    }

    /// Deploys a script directly into the node's ledger, generating a new Uuid.
    pub fn deploy_script(&self, script: String) -> Result<uuid::Uuid, String> {
        let mut ledger = self.ledger.lock().unwrap();
        ledger.deploy_script(script)
    }

    /// Executes a program (smart contract) in the node's ledger.
    pub fn execute_program(
        &self,
        script_or_id: &str,
        sender_id: &str,
        payload: &str,
    ) -> Result<ProgramResult, String> {
        let mut ledger = self.ledger.lock().unwrap();
        ledger.execute_program(script_or_id, sender_id, payload)
    }

    /// Submits and broadcasts an extrinsic across the network after adding to local mempool.
    pub async fn broadcast_extrinsic(&self, extrinsic: Extrinsic) -> Result<(), Box<dyn std::error::Error>> {
        self.mempool.lock().unwrap().push(extrinsic.clone());
        self.broadcast(&NetworkMessage::BroadcastTransaction(extrinsic)).await?;
        Ok(())
    }

    /// Proposes a block through consensus: nominates the block's hash and broadcasts both block and consensus message.
    pub async fn propose_block_consensus(
        &self,
        block: Block,
    ) -> Result<ConsensusMessage, Box<dyn std::error::Error>> {
        let mut msg = {
            let mut ledger = self.ledger.lock().unwrap();
            ledger.nominate_block(&block)?
        };
        msg.sign(&self.wallet);
        self.broadcast(&NetworkMessage::ConsensusMessage(msg.clone()))
            .await?;
        self.broadcast(&NetworkMessage::ProposeBlock(block)).await?;
        Ok(msg)
    }

    /// Directly processes a consensus message in the node's ledger.
    pub fn process_consensus_message(
        &self,
        msg: ConsensusMessage,
    ) -> Result<Option<ConsensusMessage>, String> {
        let mut ledger = self.ledger.lock().unwrap();
        ledger.consensus.process_message(msg)
    }

    // --- Event Loop ---

    pub async fn start_p2p_loop(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Blockchain P2P engine active for DID: {}...", self.did);
        let mut rx = self.event_receiver.lock().await;

        while let Some(event) = rx.recv().await {
            if let Err(e) = self.handle_event(event).await {
                eprintln!("Error handling P2P event: {}", e);
            }
        }
        Ok(())
    }

    async fn handle_event(&self, event: NodeEvent) -> Result<(), Box<dyn std::error::Error>> {
        match event {
            NodeEvent::MessageReceived { source, message } => match message {
                NetworkMessage::BroadcastTransaction(tx) => {
                    let mut mempool = self.mempool.lock().unwrap();
                    if !mempool.contains(&tx) && self.wallet.verify_signature(&tx) {
                        println!("Valid transaction gossip from {}: {}", source, tx.id);
                        mempool.push(tx);
                    }
                }

                NetworkMessage::ProposeBlock(block) => {
                    let mut ledger = self.ledger.lock().unwrap();
                    if ledger.add_block(block.clone()).is_ok() {
                        println!("Appended block #{} from {}", block.block_height, source);
                        let _ = ledger.push_extrinsics(&block.transactions);
                        self.mempool
                            .lock()
                            .unwrap()
                            .remove_batch(&block.transactions);
                    } else {
                        println!(
                            "Rejected candidate block #{} from {}",
                            block.block_height, source
                        );
                    }
                }

                NetworkMessage::ConsensusMessage(msg) => {
                    let reply_opt = {
                        let mut ledger = self.ledger.lock().unwrap();
                        match ledger.consensus.process_message(msg) {
                            Ok(reply) => reply,
                            Err(e) => {
                                eprintln!("Error processing consensus message: {}", e);
                                None
                            }
                        }
                    };

                    if let Some(mut reply) = reply_opt {
                        reply.sign(&self.wallet);
                        let _ = self
                            .broadcast(&NetworkMessage::ConsensusMessage(reply))
                            .await;
                    }
                }

                NetworkMessage::RequestChainSync { current_height } => {
                    let sync_blocks = {
                        let ledger = self.ledger.lock().unwrap();
                        if current_height < ledger.blocks.len() as u64 {
                            Some(ledger.blocks[current_height as usize..].to_vec())
                        } else {
                            None
                        }
                    };

                    if let Some(blocks) = sync_blocks {
                        let _ = self
                            .send_to(source, &NetworkMessage::ResponseChainSync { blocks })
                            .await;
                    }
                }

                NetworkMessage::ResponseChainSync { blocks } => {
                    let mut ledger = self.ledger.lock().unwrap();
                    let mut mempool = self.mempool.lock().unwrap();

                    for block in blocks {
                        if ledger.add_block(block.clone()).is_ok() {
                            let _ = ledger.push_extrinsics(&block.transactions);
                            mempool.remove_batch(&block.transactions);
                        }
                    }
                }
            },

            NodeEvent::PeerConnected(peer) => {
                println!("Established P2P Chord link with peer: {}", peer);
                let _ = self.request_chain_sync(peer).await;
            }

            NodeEvent::PeerDisconnected(peer) => {
                println!("Peer disconnected: {}", peer);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::MessageType;
    use crate::extrinsic::Context;

    #[tokio::test]
    async fn test_node_creation() {
        let wallet = Wallet::new();
        let node = Node::new(wallet, None).await.expect("Failed to create node");
        assert!(!node.peer_id().is_empty());
        assert_eq!(node.ledger.lock().unwrap().blocks.len(), 1);
        assert_eq!(node.ledger.lock().unwrap().consensus.current_slot, 1);
    }

    #[tokio::test]
    async fn test_network_message_rkyv_roundtrip() {
        let wallet = Wallet::new();
        let receiver = Wallet::new();
        let tx = wallet.new_extrinsic(receiver.public_key_hex(), 100, Context::TransferAssets);
        let msg = NetworkMessage::BroadcastTransaction(tx.clone());

        let bytes = msg.to_bytes().expect("Serialization failed");
        let decoded = NetworkMessage::from_bytes(&bytes).expect("Deserialization failed");

        assert_eq!(msg, decoded);
    }

    #[tokio::test]
    async fn test_consensus_network_message_rkyv_roundtrip() {
        let wallet = Wallet::new();
        let mut consensus_msg = ConsensusMessage::new(
            1,
            wallet.public_key_hex(),
            MessageType::Nominate,
            "val123".to_string(),
        );
        consensus_msg.sign(&wallet);

        let net_msg = NetworkMessage::ConsensusMessage(consensus_msg.clone());
        let bytes = net_msg.to_bytes().expect("Serialization failed");
        let decoded = NetworkMessage::from_bytes(&bytes).expect("Deserialization failed");

        assert_eq!(net_msg, decoded);
    }

    #[tokio::test]
    async fn test_handle_gossip_transaction() {
        let wallet = Wallet::new();
        let node = Node::new(wallet, None).await.unwrap();

        let sender = Wallet::new();
        let receiver = Wallet::new();
        let tx = sender.new_extrinsic(receiver.public_key_hex(), 50, Context::TransferAssets);

        let event = NodeEvent::MessageReceived {
            source: node.did,
            message: NetworkMessage::BroadcastTransaction(tx.clone()),
        };

        node.handle_event(event).await.unwrap();

        let mempool = node.mempool.lock().unwrap();
        assert!(mempool.contains(&tx));
    }

    #[tokio::test]
    async fn test_handle_propose_block() {
        let wallet = Wallet::new();
        let node = Node::new(wallet, None).await.unwrap();

        let genesis_hash = node.ledger.lock().unwrap().blocks[0]
            .hash_data()
            .to_string();
        let block1 = node.wallet.new_block(vec![], genesis_hash, 1);

        let event = NodeEvent::MessageReceived {
            source: node.did,
            message: NetworkMessage::ProposeBlock(block1.clone()),
        };

        node.handle_event(event).await.unwrap();

        let ledger = node.ledger.lock().unwrap();
        assert_eq!(ledger.blocks.len(), 2);
        assert_eq!(ledger.blocks[1].block_height, 1);
        assert_eq!(ledger.consensus.current_slot, 2);
    }

    #[tokio::test]
    async fn test_handle_consensus_message() {
        let wallet = Wallet::new();
        let peer_wallet = Wallet::new();

        // Configure node with a 2-validator quorum set
        let qset = QuorumSet::new(
            2,
            vec![wallet.public_key.clone(), peer_wallet.public_key.clone()],
        );
        let config = NodeConfig::default().with_quorum_set(qset);
        let node = Node::new(wallet, Some(config)).await.unwrap();

        let mut nom_msg = ConsensusMessage::new(
            1,
            peer_wallet.public_key_hex(),
            MessageType::Nominate,
            "candidate_val".to_string(),
        );
        nom_msg.sign(&peer_wallet);

        let event = NodeEvent::MessageReceived {
            source: node.did,
            message: NetworkMessage::ConsensusMessage(nom_msg),
        };

        node.handle_event(event).await.unwrap();

        let ledger = node.ledger.lock().unwrap();
        let slot_state = ledger.consensus.get_slot_state(1).unwrap();
        assert_eq!(
            slot_state.nominations.get("candidate_val").unwrap().len(),
            1
        );
    }

    #[tokio::test]
    async fn test_node_propose_consensus_value() {
        let wallet = Wallet::new();
        let node = Node::new(wallet, None).await.unwrap();

        let msg = node
            .propose_consensus_value(1, "my_block_hash".to_string())
            .await
            .unwrap();

        assert_eq!(msg.slot, 1);
        assert_eq!(msg.value, "my_block_hash");
        assert!(msg.verify_signature());

        let ledger = node.ledger.lock().unwrap();
        assert!(ledger.consensus.is_slot_externalized(1));
    }

    #[tokio::test]
    async fn test_handle_chain_sync() {
        let wallet = Wallet::new();
        let node1 = Node::new(wallet, None).await.unwrap();

        let genesis_block = node1.ledger.lock().unwrap().blocks[0].clone();
        let genesis_hash = genesis_block.hash_data().to_string();
        let block1 = node1.wallet.new_block(vec![], genesis_hash, 1);
        node1
            .ledger
            .lock()
            .unwrap()
            .add_block(block1.clone())
            .unwrap();

        let wallet2 = Wallet::new();
        let node2 = Node::new_with_genesis_block(wallet2, None, genesis_block)
            .await
            .unwrap();
        assert_eq!(node2.ledger.lock().unwrap().blocks.len(), 1);

        let event = NodeEvent::MessageReceived {
            source: node1.did,
            message: NetworkMessage::ResponseChainSync {
                blocks: vec![block1],
            },
        };

        node2.handle_event(event).await.unwrap();
        assert_eq!(node2.ledger.lock().unwrap().blocks.len(), 2);
    }

    #[tokio::test]
    async fn test_node_deploy_and_execute_program() {
        let wallet = Wallet::new();
        let node = Node::new(wallet, None).await.unwrap();
        let caller = Wallet::new();
        let recipient = Wallet::new();

        node.ledger
            .lock()
            .unwrap()
            .accounts
            .credit_balance(&caller.public_key, 200);

        let script = r#"
def execute(sender, payload):
    return {
        "status": "success",
        "state_changes": [
            {
                "action": "transfer",
                "to_address": payload,
                "amount": 75,
            }
        ]
    }
"#;

        let prog_id = uuid::Uuid::new_v4();
        node.deploy_program(prog_id, script.to_string())
            .unwrap();

        let result = node.execute_program(
            &prog_id.to_string(),
            &caller.public_key_hex(),
            &recipient.public_key_hex(),
        );

        assert!(result.is_ok());
        let ledger = node.ledger.lock().unwrap();
        assert_eq!(ledger.accounts.get_balance_by_address(&caller.public_key_hex()), 125);
        assert_eq!(ledger.accounts.get_balance_by_address(&recipient.public_key_hex()), 75);
    }

    #[tokio::test]
    async fn test_node_block_with_contract_extrinsic_applied() {
        let wallet = Wallet::new();
        let node = Node::new(wallet, None).await.unwrap();

        let sender = Wallet::new();
        let recipient = Wallet::new();

        node.ledger
            .lock()
            .unwrap()
            .accounts
            .credit_balance(&sender.public_key, 100);

        let tx = sender.new_extrinsic(recipient.public_key_hex(), 40, Context::TransferAssets);

        let genesis_hash = node.ledger.lock().unwrap().blocks[0]
            .hash_data()
            .to_string();
        let block1 = node.wallet.new_block(vec![tx], genesis_hash, 1);

        let event = NodeEvent::MessageReceived {
            source: node.did,
            message: NetworkMessage::ProposeBlock(block1),
        };

        node.handle_event(event).await.unwrap();

        let mut ledger = node.ledger.lock().unwrap();
        assert_eq!(ledger.blocks.len(), 2);
        assert_eq!(ledger.accounts.get_balance(&sender.public_key), 60);
        assert_eq!(ledger.accounts.get_balance(&recipient.public_key), 40);
    }
}