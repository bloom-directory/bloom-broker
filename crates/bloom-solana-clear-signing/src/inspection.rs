//! Structural readings from actual signed Solana message bytes. Lookup table
//! references remain unresolved; IDL names do not establish program code,
//! token identity, account ownership, simulation or settlement.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::OnceLock;

use crate::{
    Pubkey,
    message::{ParseError, ParsedMessage, parse_versioned_message},
};

const SYSTEM: &str = "11111111111111111111111111111111";
const COMPUTE: &str = "ComputeBudget111111111111111111111111111111";
const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const ASSOCIATED: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Field {
    pub name: String,
    /// Integers are decimal strings, preserving u64/u128 precision in browsers.
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountReading {
    pub index: u8,
    pub role: String,
    pub address: Option<Pubkey>,
    pub lookup: Option<String>,
    pub signer: bool,
    pub writable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstructionReading {
    pub program: Pubkey,
    pub name: Option<String>,
    pub accounts: Vec<AccountReading>,
    pub fields: Vec<Field>,
    pub data_hex: String,
    pub warning: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageReading {
    pub version: Option<u8>,
    pub fee_payer: Pubkey,
    pub signers: Vec<Pubkey>,
    pub recent_blockhash: String,
    pub payload_sha256: String,
    pub blockhash_independent_sha256: String,
    pub instructions: Vec<InstructionReading>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Catalog {
    programs: Vec<Program>,
}
#[derive(Debug, Deserialize)]
struct Program {
    address: Pubkey,
    name: String,
    instructions: Vec<Instruction>,
}
#[derive(Debug, Deserialize)]
struct Instruction {
    name: String,
    discriminator: [u8; 8],
    accounts: Vec<String>,
    args: Vec<Argument>,
}
#[derive(Debug, Deserialize)]
struct Argument {
    name: String,
    #[serde(rename = "type")]
    kind: Value,
}

fn catalog() -> &'static Catalog {
    static CATALOG: OnceLock<Catalog> = OnceLock::new();
    CATALOG.get_or_init(|| {
        serde_json::from_str(include_str!("../catalogs/pump.json"))
            .expect("compiled Pump reading catalog must be valid")
    })
}

pub fn inspect(bytes: &[u8]) -> Result<MessageReading, ParseError> {
    let parsed = parse_versioned_message(bytes)?;
    let message = &parsed.message;
    let mut warnings = vec![
        "Structural reading: program code, token identity/decimals, account state, CPI effects and settlement are unverified.".into(),
        "Cluster, blockhash freshness and base fees are not established by this message.".into(),
    ];
    if !parsed.lookups.is_empty() {
        warnings.push(
            "Lookup addresses remain unresolved; the message binds table/index references.".into(),
        );
    }
    let instructions = message.instructions.iter().map(|ix| {
        let program = message.account_keys[usize::from(ix.program_id_index)];
        let decoded = decode_instruction(program, &ix.data);
        let (name, roles, fields, warning) = match decoded {
            Ok(Some((name, roles, fields))) if ix.accounts.len() >= roles.len() =>
                (Some(name), roles, fields, None),
            Ok(Some(_)) => (None, vec![], vec![], Some("Instruction has fewer accounts than its published layout; roles and arguments are not attributed.".into())),
            Ok(None) => (None, vec![], vec![], Some("No compiled reading for this program/instruction; exact bytes and account roles are retained.".into())),
            Err(reason) => (None, vec![], vec![], Some(reason)),
        };
        let accounts = ix.accounts.iter().enumerate().map(|(position, index)| {
            account(&parsed, *index, roles.get(position).cloned()
                .unwrap_or_else(|| format!("remaining account {}", position + 1)))
        }).collect();
        InstructionReading { program, name, accounts, fields, data_hex: hex::encode(&ix.data), warning }
    }).collect();
    Ok(MessageReading {
        version: parsed.version,
        fee_payer: message.fee_payer(),
        signers: message.account_keys[..usize::from(message.header.num_required_signatures)]
            .to_vec(),
        recent_blockhash: bs58::encode(message.recent_blockhash).into_string(),
        payload_sha256: hex::encode(crate::message_digest(bytes)),
        blockhash_independent_sha256: hex::encode(parsed.blockhash_independent_digest()),
        instructions,
        warnings,
    })
}

fn account(parsed: &ParsedMessage, index: u8, role: String) -> AccountReading {
    let index_usize = usize::from(index);
    let message = &parsed.message;
    let signed = usize::from(message.header.num_required_signatures);
    if let Some(address) = message.account_keys.get(index_usize) {
        let signer = index_usize < signed;
        let writable = if signer {
            index_usize < signed - usize::from(message.header.num_readonly_signed_accounts)
        } else {
            index_usize
                < message.account_keys.len()
                    - usize::from(message.header.num_readonly_unsigned_accounts)
        };
        return AccountReading {
            index,
            role,
            address: Some(*address),
            lookup: None,
            signer,
            writable,
        };
    }
    let mut loaded_index = index_usize - message.account_keys.len();
    // v0 loads all writable entries across all tables, then all readonly ones.
    for writable in [true, false] {
        for table in &parsed.lookups {
            let indices = if writable {
                &table.writable_indices
            } else {
                &table.readonly_indices
            };
            if let Some(entry) = indices.get(loaded_index) {
                return AccountReading {
                    index,
                    role,
                    address: None,
                    lookup: Some(format!("{}[{}]", table.table, entry)),
                    signer: false,
                    writable,
                };
            }
            loaded_index -= indices.len();
        }
    }
    unreachable!("parser checked the complete account index range")
}

type Decoded = (String, Vec<String>, Vec<Field>);

fn decode_instruction(program: Pubkey, data: &[u8]) -> Result<Option<Decoded>, String> {
    if let Some(known) = catalog().programs.iter().find(|p| p.address == program) {
        let Some(instruction) = known
            .instructions
            .iter()
            .find(|i| data.starts_with(&i.discriminator))
        else {
            return Ok(None);
        };
        let mut cursor = Cursor(&data[8..]);
        let mut fields = Vec::new();
        for arg in &instruction.args {
            let value = cursor.argument(&arg.kind)?;
            fields.push(Field {
                name: arg.name.clone(),
                value,
            });
        }
        cursor.finish()?;
        return Ok(Some((
            format!("{} · {}", known.name, instruction.name),
            instruction.accounts.clone(),
            fields,
        )));
    }
    let address = program.to_string();
    let mut cursor = Cursor(data);
    let mut fields = Vec::new();
    let (name, roles): (&str, &[&str]) = match address.as_str() {
        SYSTEM => match cursor.uint(4)? {
            2 => {
                fields.push(cursor.field("lamports", 8)?);
                ("System · transfer", &["source", "destination"])
            }
            0 => {
                fields.push(cursor.field("lamports", 8)?);
                fields.push(cursor.field("space", 8)?);
                fields.push(Field {
                    name: "owner program".into(),
                    value: cursor.pubkey()?,
                });
                (
                    "System · create account",
                    &["funding account", "new account"],
                )
            }
            _ => return Ok(None),
        },
        COMPUTE => match cursor.uint(1)? {
            2 => {
                fields.push(cursor.field("compute unit limit", 4)?);
                ("Compute budget · unit limit", &[])
            }
            3 => {
                fields.push(cursor.field("micro-lamports per compute unit", 8)?);
                ("Compute budget · unit price", &[])
            }
            _ => return Ok(None),
        },
        TOKEN | TOKEN_2022 => match cursor.uint(1)? {
            9 => (
                "Token · close account",
                &["token account", "rent recipient", "authority"],
            ),
            17 => ("Token · sync native", &["wrapped SOL account"]),
            3 => {
                fields.push(cursor.field("amount (raw token units)", 8)?);
                (
                    "Token · transfer",
                    &[
                        "source token account",
                        "destination token account",
                        "authority",
                    ],
                )
            }
            12 => {
                fields.push(cursor.field("amount (raw token units)", 8)?);
                fields.push(cursor.field("instruction decimals (not independently verified)", 1)?);
                (
                    "Token · transfer checked",
                    &[
                        "source token account",
                        "mint",
                        "destination token account",
                        "authority",
                    ],
                )
            }
            _ => return Ok(None),
        },
        ASSOCIATED => match data {
            [] => (
                "Associated token · create",
                &[
                    "funding account",
                    "token account",
                    "wallet",
                    "mint",
                    "system program",
                    "token program",
                ],
            ),
            [1] => {
                cursor.take(1)?;
                (
                    "Associated token · create idempotent",
                    &[
                        "funding account",
                        "token account",
                        "wallet",
                        "mint",
                        "system program",
                        "token program",
                    ],
                )
            }
            _ => return Ok(None),
        },
        _ => return Ok(None),
    };
    cursor.finish()?;
    Ok(Some((
        name.into(),
        roles.iter().map(|r| (*r).into()).collect(),
        fields,
    )))
}

struct Cursor<'a>(&'a [u8]);
impl<'a> Cursor<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], String> {
        let bytes = self
            .0
            .get(..count)
            .ok_or("Instruction data is truncated; exact bytes remain available.")?;
        self.0 = &self.0[count..];
        Ok(bytes)
    }
    fn uint(&mut self, count: usize) -> Result<u128, String> {
        let mut bytes = [0; 16];
        bytes[..count].copy_from_slice(self.take(count)?);
        Ok(u128::from_le_bytes(bytes))
    }
    fn pubkey(&mut self) -> Result<String, String> {
        Ok(bs58::encode(self.take(32)?).into_string())
    }
    fn field(&mut self, name: &str, count: usize) -> Result<Field, String> {
        Ok(Field {
            name: name.into(),
            value: self.uint(count)?.to_string(),
        })
    }
    fn argument(&mut self, kind: &Value) -> Result<String, String> {
        if let Some(alias) = kind
            .get("defined")
            .and_then(|d| d.get("name"))
            .and_then(Value::as_str)
            && matches!(alias, "OptionBool" | "OptionU64")
        {
            if self.0.is_empty() {
                return Ok("Not encoded; program determines the default".into());
            }
            return self.argument(&Value::String(
                if alias == "OptionBool" { "bool" } else { "u64" }.into(),
            ));
        }
        match kind.as_str() {
            Some("u8") => Ok(self.uint(1)?.to_string()),
            Some("u16") => Ok(self.uint(2)?.to_string()),
            Some("u32") => Ok(self.uint(4)?.to_string()),
            Some("u64") => Ok(self.uint(8)?.to_string()),
            Some("u128") => Ok(self.uint(16)?.to_string()),
            Some("bool") => match self.uint(1)? {
                0 => Ok("false".into()),
                1 => Ok("true".into()),
                _ => Err("Instruction boolean is not canonical.".into()),
            },
            Some("pubkey") => self.pubkey(),
            Some("string") => {
                let length = self.uint(4)? as usize;
                let text = std::str::from_utf8(self.take(length)?)
                    .map_err(|_| "Instruction string is not UTF-8.")?;
                // JSON spelling makes control/bidi characters visible, never UI controls.
                let mut visible = String::new();
                for c in text.chars() {
                    if c.is_control()
                        || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
                    {
                        visible.extend(c.escape_unicode());
                    } else {
                        visible.push(c);
                    }
                }
                Ok(visible)
            }
            _ => Err("Instruction argument type has no compiled reading.".into()),
        }
    }
    fn finish(&self) -> Result<(), String> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err("Instruction has unrecognized trailing data; exact bytes remain available.".into())
        }
    }
}
