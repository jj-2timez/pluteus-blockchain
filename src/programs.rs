use rkyv::{Archive, Deserialize, Serialize};
use starlark::environment::{Globals, Module};
use starlark::eval::Evaluator;
use starlark::syntax::{AstModule, Dialect};
use starlark::values::Value;

#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
#[rkyv(crate = rkyv)]
pub struct StateChange {
    pub action: String,       
    pub to_address: String,   
    pub amount: u64,
}

impl StateChange {
    pub fn new(action: impl Into<String>, to_address: impl Into<String>, amount: u64) -> Self {
        Self {
            action: action.into(),
            to_address: to_address.into(),
            amount,
        }
    }

    pub fn to_bytes(&self) -> Result<rkyv::util::AlignedVec, rkyv::rancor::Error> {
        rkyv::to_bytes::<rkyv::rancor::Error>(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, rkyv::rancor::Error> {
        rkyv::from_bytes::<Self, rkyv::rancor::Error>(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
#[rkyv(crate = rkyv)]
pub struct ProgramResult {
    pub status: String,
    pub state_changes: Vec<StateChange>,
}

impl ProgramResult {
    pub fn new(status: impl Into<String>, state_changes: Vec<StateChange>) -> Self {
        Self {
            status: status.into(),
            state_changes,
        }
    }

    pub fn to_bytes(&self) -> Result<rkyv::util::AlignedVec, rkyv::rancor::Error> {
        rkyv::to_bytes::<rkyv::rancor::Error>(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, rkyv::rancor::Error> {
        rkyv::from_bytes::<Self, rkyv::rancor::Error>(bytes)
    }
}

pub struct ProgramTransformer;

impl ProgramTransformer {
    /// Executes a Starlark script, extracts variables directly from the VM heap, 
    /// and returns strictly zero-copy Rkyv bytes.
    pub fn execute_program(
        script: &str,
        sender_id: &str,
        payload_data: &str,
    ) -> Result<Vec<u8>, String> {
        let ast = AstModule::parse("contract.star", script.to_owned(), &Dialect::Standard)
            .map_err(|e| format!("Failed to parse AST: {}", e))?;

        let globals = Globals::standard();

        Module::with_temp_heap(|module| {
            let mut eval = Evaluator::new(&module);

            eval.eval_module(ast, &globals)
                .map_err(|e| format!("Failed to initialize module: {}", e))?;

            let execute_fn = module
                .get("execute")
                .ok_or_else(|| "Contract must define an 'execute(sender, payload)' function".to_string())?;

            let heap = eval.heap();

            // Allocate standard inputs into the VM's heap
            let sender_val = heap.alloc(sender_id);
            let payload_val = heap.alloc(payload_data);

            // Run the contract and get the raw Starlark Value pointer
            let result: Value = eval
                .eval_function(execute_fn, &[sender_val, payload_val], &[])
                .map_err(|e| format!("Contract runtime error: {}", e))?;

            fn get_val<'v>(dict: Value<'v>, heap: starlark::values::Heap<'v>, key: &str) -> Option<Value<'v>> {
                let key_val = heap.alloc(key);
                dict.at(key_val, heap).ok()
            }

            // 1. Extract the status string
            let status = get_val(result, heap, "status")
                .and_then(|v| v.unpack_str())
                .unwrap_or("failed")
                .to_string();

            // 2. Extract and iterate over the state_changes list
            let mut state_changes = Vec::new();

            if let Some(changes_list) = get_val(result, heap, "state_changes") {
                let len = changes_list.length().unwrap_or(0);

                for i in 0..len {
                    let index_val = heap.alloc(i);

                    // Read the item out of the Starlark array
                    if let Ok(item) = changes_list.at(index_val, heap) {
                        let action = get_val(item, heap, "action")
                            .and_then(|v| v.unpack_str())
                            .unwrap_or("")
                            .to_string();

                        let to_address = get_val(item, heap, "to_address")
                            .and_then(|v| v.unpack_str())
                            .unwrap_or("")
                            .to_string();

                        let amount = get_val(item, heap, "amount")
                            .and_then(|v| {
                                v.unpack_i32()
                                    .map(|i| i as u64)
                                    .or_else(|| v.unpack_str().and_then(|s| s.parse::<u64>().ok()))
                            })
                            .unwrap_or(0);

                        state_changes.push(StateChange {
                            action,
                            to_address,
                            amount,
                        });
                    }
                }
            }

            let contract_struct = ProgramResult {
                status,
                state_changes,
            };

            // Binary serialization via rkyv
            let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&contract_struct)
                .map_err(|e| format!("Failed to serialize contract result via Rkyv: {}", e))?;

            Ok(bytes.into_vec())
        })
    }

    /// Executes a Starlark script and deserializes the Rkyv bytes directly into ProgramResult.
    pub fn execute_and_deserialize(
        script: &str,
        sender_id: &str,
        payload_data: &str,
    ) -> Result<ProgramResult, String> {
        let bytes = Self::execute_program(script, sender_id, payload_data)?;
        ProgramResult::from_bytes(&bytes)
            .map_err(|e| format!("Failed to deserialize ProgramResult from rkyv bytes: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execute_valid_starlark_contract() {
        let script = r#"
def execute(sender, payload):
    return {
        "status": "success",
        "state_changes": [
            {
                "action": "transfer",
                "to_address": "recipient_addr_123",
                "amount": 100,
            }
        ]
    }
"#;
        let bytes = ProgramTransformer::execute_program(script, "sender_456", "payload_test")
            .expect("Contract should execute successfully");

        let result = ProgramResult::from_bytes(&bytes).expect("Should deserialize via rkyv");
        assert_eq!(result.status, "success");
        assert_eq!(result.state_changes.len(), 1);
        assert_eq!(result.state_changes[0].action, "transfer");
        assert_eq!(result.state_changes[0].to_address, "recipient_addr_123");
        assert_eq!(result.state_changes[0].amount, 100);
    }

    #[test]
    fn test_execute_and_deserialize_helper() {
        let script = r#"
def execute(sender, payload):
    return {
        "status": "success",
        "state_changes": [
            {
                "action": "credit",
                "to_address": sender,
                "amount": 250,
            },
            {
                "action": "transfer",
                "to_address": "vault_addr",
                "amount": 50,
            }
        ]
    }
"#;
        let result = ProgramTransformer::execute_and_deserialize(script, "sender_alice", "deposit")
            .expect("Execution should succeed");

        assert_eq!(result.status, "success");
        assert_eq!(result.state_changes.len(), 2);
        assert_eq!(result.state_changes[0].action, "credit");
        assert_eq!(result.state_changes[0].to_address, "sender_alice");
        assert_eq!(result.state_changes[0].amount, 250);
        assert_eq!(result.state_changes[1].action, "transfer");
        assert_eq!(result.state_changes[1].to_address, "vault_addr");
        assert_eq!(result.state_changes[1].amount, 50);
    }

    #[test]
    fn test_contract_missing_execute_function() {
        let script = r#"
def other_function():
    return 42
"#;
        let err = ProgramTransformer::execute_program(script, "sender_id", "")
            .expect_err("Should error when execute() is missing");

        assert!(err.contains("Contract must define an 'execute(sender, payload)' function"));
    }

    #[test]
    fn test_contract_syntax_error() {
        let script = "def execute(sender, payload) this is broken syntax";
        let err = ProgramTransformer::execute_program(script, "sender_id", "")
            .expect_err("Should error on invalid AST");

        assert!(err.contains("Failed to parse AST"));
    }

    #[test]
    fn test_contract_runtime_error() {
        let script = r#"
def execute(sender, payload):
    x = 1 / 0
    return {"status": "success", "state_changes": []}
"#;
        let err = ProgramTransformer::execute_program(script, "sender_id", "")
            .expect_err("Should error on divide by zero");

        assert!(err.contains("Contract runtime error"));
    }

    #[test]
    fn test_program_result_rkyv_roundtrip() {
        let result = ProgramResult::new(
            "success",
            vec![
                StateChange::new("transfer", "addr_1", 10),
                StateChange::new("mint", "addr_2", 200),
            ],
        );

        let bytes = result.to_bytes().expect("Serialization should succeed");
        let decoded = ProgramResult::from_bytes(&bytes).expect("Deserialization should succeed");

        assert_eq!(result, decoded);
    }

    #[test]
    fn test_state_change_rkyv_roundtrip() {
        let change = StateChange::new("burn", "addr_burn", 500);
        let bytes = change.to_bytes().expect("Serialization should succeed");
        let decoded = StateChange::from_bytes(&bytes).expect("Deserialization should succeed");

        assert_eq!(change, decoded);
    }
}