use bloom_solana_clear_signing::{
    Pubkey, inspection,
    message::{self, ParsedMessage},
};
use bloom_solana_verify::golden;
use serde_json::Value;

fn fixtures() -> Value {
    serde_json::from_str(include_str!("pump-messages.json")).unwrap()
}

#[test]
fn real_builder_messages_roundtrip_and_read_the_signed_arguments() {
    for (name, fixture) in fixtures()["fixtures"].as_object().unwrap() {
        let bytes = hex::decode(fixture["message_hex"].as_str().unwrap()).unwrap();
        let parsed = message::parse_versioned_message(&bytes).unwrap();
        assert_eq!(parsed.serialize(), bytes, "{name}");
        let reading = inspection::inspect(&bytes).unwrap();
        assert_eq!(reading.fee_payer, parsed.message.fee_payer());
        assert_eq!(
            reading.instructions.len(),
            parsed.message.instructions.len()
        );
        assert!(
            reading
                .instructions
                .iter()
                .any(|i| i.name.as_deref().is_some_and(|n| n.starts_with("Pump"))),
            "{name}: {reading:?}"
        );
        for instruction in &reading.instructions {
            assert!(instruction.name.is_some(), "{name}: {instruction:?}");
            assert!(instruction.warning.is_none(), "{name}: {instruction:?}");
            assert_eq!(instruction.data_hex.len() % 2, 0);
        }
    }
}

#[test]
fn v0_codec_matches_the_independent_anza_reference() {
    use solana_message::{
        Address, Hash, MessageHeader, VersionedMessage, compiled_instruction, v0,
    };
    for fixture in fixtures()["fixtures"].as_object().unwrap().values() {
        let bytes = hex::decode(fixture["message_hex"].as_str().unwrap()).unwrap();
        let parsed = message::parse_versioned_message(&bytes).unwrap();
        let header = parsed.message.header;
        let reference = VersionedMessage::V0(v0::Message {
            header: MessageHeader {
                num_required_signatures: header.num_required_signatures,
                num_readonly_signed_accounts: header.num_readonly_signed_accounts,
                num_readonly_unsigned_accounts: header.num_readonly_unsigned_accounts,
            },
            account_keys: parsed
                .message
                .account_keys
                .iter()
                .map(|k| Address::from(k.to_bytes()))
                .collect(),
            recent_blockhash: Hash::new_from_array(parsed.message.recent_blockhash),
            instructions: parsed
                .message
                .instructions
                .iter()
                .map(|i| compiled_instruction::CompiledInstruction {
                    program_id_index: i.program_id_index,
                    accounts: i.accounts.clone(),
                    data: i.data.clone(),
                })
                .collect(),
            address_table_lookups: parsed
                .lookups
                .iter()
                .map(|l| v0::MessageAddressTableLookup {
                    account_key: Address::from(l.table.to_bytes()),
                    writable_indexes: l.writable_indices.clone(),
                    readonly_indexes: l.readonly_indices.clone(),
                })
                .collect(),
        });
        reference.sanitize().unwrap();
        assert_eq!(reference.serialize(), bytes);
    }
}

#[test]
fn every_accepted_byte_mutation_outside_blockhash_changes_the_binding() {
    for fixture in fixtures()["fixtures"].as_object().unwrap().values() {
        let bytes = hex::decode(fixture["message_hex"].as_str().unwrap()).unwrap();
        let parsed = message::parse_versioned_message(&bytes).unwrap();
        let prefix = usize::from(parsed.version.is_some());
        let mut cursor = prefix + 3;
        let accounts = bloom_solana_clear_signing::read_short_vec(&bytes, &mut cursor).unwrap();
        let blockhash_start = cursor + usize::from(accounts) * 32;
        let digest = parsed.blockhash_independent_digest();
        for offset in 0..bytes.len() {
            let mut changed = bytes.clone();
            changed[offset] ^= 1;
            if let Ok(changed) = message::parse_versioned_message(&changed) {
                assert_eq!(
                    changed.blockhash_independent_digest() == digest,
                    (blockhash_start..blockhash_start + 32).contains(&offset),
                    "offset {offset}"
                );
            }
        }
    }
}

#[test]
fn normalization_excludes_only_blockhash_and_preserves_every_other_byte() {
    for fixture in fixtures()["fixtures"].as_object().unwrap().values() {
        let bytes = hex::decode(fixture["message_hex"].as_str().unwrap()).unwrap();
        let original = message::parse_versioned_message(&bytes).unwrap();
        let expected = original.blockhash_independent_digest();
        let mut changed = original.clone();
        changed.message.recent_blockhash = [0xa5; 32];
        assert_eq!(changed.blockhash_independent_digest(), expected);
        for index in 0..original.message.account_keys.len() {
            let mut changed = original.clone();
            changed.message.account_keys[index] = Pubkey::from_bytes([0x55; 32]);
            assert_ne!(changed.blockhash_independent_digest(), expected);
        }
        for index in 0..original.message.instructions.len() {
            let mut changed = original.clone();
            changed.message.instructions[index].data.push(1);
            assert_ne!(changed.blockhash_independent_digest(), expected);
        }
        if !original.lookups.is_empty() {
            let mut changed = original.clone();
            changed.lookups[0].table = Pubkey::from_bytes([0x77; 32]);
            assert_ne!(changed.blockhash_independent_digest(), expected);
        }
    }
}

#[test]
fn lookup_contents_are_never_invented_and_loaded_accounts_are_ordered() {
    let mut parsed = ParsedMessage {
        version: Some(0),
        message: message::parse_message(&golden::message_bytes()).unwrap(),
        lookups: vec![
            message::AddressTableLookup {
                table: Pubkey::from_bytes([4; 32]),
                writable_indices: vec![7],
                readonly_indices: vec![9],
            },
            message::AddressTableLookup {
                table: Pubkey::from_bytes([5; 32]),
                writable_indices: vec![8],
                readonly_indices: vec![10],
            },
        ],
    };
    parsed.message.instructions[0].accounts = vec![0, 3, 4, 5, 6];
    let reading = inspection::inspect(&parsed.serialize()).unwrap();
    let accounts = &reading.instructions[0].accounts;
    for (i, expected) in [(1, 7), (2, 8), (3, 9), (4, 10)] {
        assert!(accounts[i].address.is_none());
        assert!(
            accounts[i]
                .lookup
                .as_ref()
                .unwrap()
                .ends_with(&format!("[{expected}]"))
        );
        assert_eq!(accounts[i].writable, i <= 2);
        assert!(!accounts[i].signer);
    }
    assert!(reading.warnings.iter().any(|w| w.contains("unresolved")));
    assert!(
        message::parse_message(&parsed.serialize()).is_err(),
        "native verifier stays legacy-only"
    );
}

#[test]
fn malformed_versioned_messages_and_oversized_multisigner_packets_are_refused() {
    let legacy = message::parse_message(&golden::message_bytes()).unwrap();
    let valid = ParsedMessage {
        version: Some(0),
        message: legacy.clone(),
        lookups: vec![],
    }
    .serialize();
    for end in 0..valid.len() {
        assert!(message::parse_versioned_message(&valid[..end]).is_err());
    }
    let mut changed = valid.clone();
    changed[0] = 0x81;
    assert!(message::parse_versioned_message(&changed).is_err());
    let mut changed = valid.clone();
    changed.push(0);
    assert!(message::parse_versioned_message(&changed).is_err());
    let mut big = legacy;
    big.header.num_required_signatures = 20;
    big.header.num_readonly_unsigned_accounts = 0;
    big.account_keys.resize(20, Pubkey::from_bytes([8; 32]));
    assert!(message::parse_versioned_message(&big.serialize()).is_err());
}
