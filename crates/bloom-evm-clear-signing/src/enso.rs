//! Read the pinned Enso Weiroll command/state format, without executing calls.
//! Source: EnsoBuild/enso-weiroll@900250114203727ff236d3f6313673c17c2d90dd,
//! contracts/VM.sol and CommandBuilder.sol. Return values stay symbolic: a
//! later read of an overwritten slot must never reuse its initial literal.

use alloy_dyn_abi::{DynSolValue, JsonAbiExt};
use alloy_primitives::{Address, U256, hex};
use serde::Serialize;

use crate::ClearSignedCall;

const SIGNATURE: &str =
    "executeShortcut(bytes32 accountId,bytes32 requestId,bytes32[] commands,bytes[] state)";
const MAX_BYTES: usize = 64 * 1024;
const MAX_COMMANDS: usize = 64;

#[derive(Serialize)]
pub(crate) struct Program {
    account_id: String,
    request_id: String,
    initial_state: Vec<String>,
    pub steps: Vec<Step>,
}

#[derive(Serialize)]
pub(crate) struct Step {
    command_word: usize,
    call_type: &'static str,
    pub target: Address,
    selector: String,
    arguments: Vec<String>,
    native_value: String,
    output: String,
    #[serde(skip)]
    pub value: Option<U256>,
    #[serde(skip)]
    pub calldata: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reconstructed_calldata: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reading: Option<ClearSignedCall>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unread_reason: Option<String>,
}

#[derive(Clone)]
enum Slot {
    Literal(Vec<u8>),
    Result(String),
}

struct Argument {
    description: String,
    data: Option<Vec<u8>>,
    dynamic: bool,
}

fn slot(state: &Option<Vec<Slot>>, index: u8) -> Result<Argument, String> {
    let index = usize::from(index & 0x7f);
    match state {
        Some(state) => match state.get(index).ok_or("state index is out of bounds")? {
            Slot::Literal(bytes) => Ok(Argument {
                description: format!("state[{index}] = 0x{}", hex::encode(bytes)),
                data: Some(bytes.clone()),
                dynamic: false,
            }),
            Slot::Result(source) => Ok(Argument {
                description: format!("state[{index}] from {source}"),
                data: None,
                dynamic: false,
            }),
        },
        None => Ok(Argument {
            description: format!("state[{index}] from a preceding whole-state replacement"),
            data: None,
            dynamic: false,
        }),
    }
}

/// ABI heads/tails assembled exactly as CommandBuilder does. Unknown return
/// values prevent reconstruction; they do not become zero or an old literal.
fn encode(arguments: &[Argument]) -> Result<Option<Vec<u8>>, String> {
    for arg in arguments {
        if let Some(bytes) = &arg.data {
            if arg.dynamic && (bytes.is_empty() || bytes.len() % 32 != 0) {
                return Err("dynamic state is not a nonempty multiple of 32 bytes".into());
            }
            if !arg.dynamic && bytes.len() != 32 {
                return Err("static state is not exactly 32 bytes".into());
            }
        }
    }
    if arguments.iter().any(|arg| arg.data.is_none()) {
        return Ok(None);
    }
    let mut head = Vec::new();
    let mut tail: Vec<u8> = Vec::new();
    for arg in arguments {
        let bytes = arg.data.as_ref().unwrap();
        if arg.dynamic {
            if bytes.is_empty() || bytes.len() % 32 != 0 {
                return Err("dynamic state is not a nonempty multiple of 32 bytes".into());
            }
            head.extend(U256::from(arguments.len() * 32 + tail.len()).to_be_bytes::<32>());
            tail.extend(bytes);
        } else {
            if bytes.len() != 32 {
                return Err("static state is not exactly 32 bytes".into());
            }
            head.extend(bytes);
        }
        if head.len() + tail.len() > MAX_BYTES {
            return Err("reconstructed arguments exceed the size bound".into());
        }
    }
    head.extend(tail);
    Ok(Some(head))
}

fn state_argument(state: &Option<Vec<Slot>>) -> Result<Argument, String> {
    let data = match state {
        Some(state) if state.iter().all(|slot| matches!(slot, Slot::Literal(_))) => {
            let values = state
                .iter()
                .map(|slot| match slot {
                    Slot::Literal(bytes) => DynSolValue::Bytes(bytes.clone()),
                    _ => unreachable!(),
                })
                .collect();
            // abi.encode(bytes[]) has an outer offset; buildInputs copies
            // everything after that word into the argument's dynamic tail.
            let encoded = DynSolValue::Array(values).abi_encode();
            Some(encoded[32..].to_vec())
        }
        _ => None,
    };
    Ok(Argument {
        description: "entire current bytes[] state".into(),
        data,
        dynamic: true,
    })
}

fn arguments(
    indices: &[u8; 32],
    position: &mut usize,
    end: usize,
    state: &Option<Vec<Slot>>,
    nested: bool,
    depth: usize,
    dynamic_count: &mut usize,
) -> Result<Vec<Argument>, String> {
    if depth > 8 {
        return Err("dynamic arguments exceed the nesting bound".into());
    }
    let mut args = Vec::new();
    while *position < end {
        let index = indices[*position];
        *position += 1;
        if nested && index == 0xfb {
            return Ok(args);
        }
        if !nested && index == 0xff {
            return Ok(args);
        }
        let arg = match index {
            0xfe if nested => {
                return Err("whole state is forbidden inside a dynamic argument".into());
            }
            0xfe => state_argument(state)?,
            0xfc | 0xfd => {
                *dynamic_count += 1;
                if *dynamic_count > 10 {
                    return Err("Weiroll dynamic argument table exceeds ten entries".into());
                }
                let length = if index == 0xfd {
                    let length_index = *indices
                        .get(*position)
                        .ok_or("array length index is missing")?;
                    *position += 1;
                    let length = slot(state, length_index)?;
                    if length.data.as_ref().is_some_and(|data| data.len() != 32) {
                        return Err("array length state is not 32 bytes".into());
                    }
                    Some(length)
                } else {
                    None
                };
                let members =
                    arguments(indices, position, 32, state, true, depth + 1, dynamic_count)?;
                let mut data = encode(&members)?;
                if let Some(length) = &length {
                    data = match (length.data.as_ref(), data) {
                        (Some(length), Some(body)) => Some([length.as_slice(), &body].concat()),
                        _ => None,
                    };
                }
                Argument {
                    description: format!(
                        "{}{} [{}]",
                        if index == 0xfd { "array" } else { "tuple" },
                        length
                            .as_ref()
                            .map(|a| format!(" length {}", a.description))
                            .unwrap_or_default(),
                        members
                            .iter()
                            .map(|a| a.description.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    data,
                    dynamic: true,
                }
            }
            _ => {
                let mut arg = slot(state, index)?;
                arg.dynamic = index & 0x80 != 0;
                if arg.dynamic {
                    arg.description = format!("dynamic {}", arg.description);
                }
                arg
            }
        };
        args.push(arg);
    }
    if nested {
        return Err("dynamic argument is missing its closing marker".into());
    }
    Ok(args)
}

pub(crate) fn decode(data: &[u8]) -> Result<Program, String> {
    if data.len() > MAX_BYTES {
        return Err("shortcut exceeds 64 KiB".into());
    }
    let function = crate::parse_function(SIGNATURE).map_err(|error| error.detail)?;
    if data.get(..4) != Some(function.selector().as_slice()) {
        return Err("unknown shortcut entry-point selector".into());
    }
    let values = function
        .abi_decode_input(&data[4..])
        .map_err(|_| "malformed executeShortcut arguments")?;
    if function
        .abi_encode_input(&values)
        .map_err(|_| "shortcut re-encoding failed")?
        != data
    {
        return Err("shortcut ABI is not canonical".into());
    }
    let [
        DynSolValue::FixedBytes(account, 32),
        DynSolValue::FixedBytes(request, 32),
        DynSolValue::Array(commands),
        DynSolValue::Array(initial),
    ] = values.as_slice()
    else {
        return Err("invalid shortcut argument types".into());
    };
    if commands.len() > MAX_COMMANDS || initial.len() > 128 {
        return Err("shortcut command/state count exceeds the bound".into());
    }
    let mut state = Some(
        initial
            .iter()
            .map(|value| match value {
                DynSolValue::Bytes(bytes) => Ok(Slot::Literal(bytes.clone())),
                _ => Err("invalid state type"),
            })
            .collect::<Result<Vec<_>, _>>()?,
    );
    let mut program = Program {
        account_id: format!("0x{}", hex::encode(account)),
        request_id: format!("0x{}", hex::encode(request)),
        initial_state: initial
            .iter()
            .map(|v| match v {
                DynSolValue::Bytes(bytes) => format!("0x{}", hex::encode(bytes)),
                _ => unreachable!(),
            })
            .collect(),
        steps: Vec::new(),
    };
    let mut cursor = 0;
    while cursor < commands.len() {
        let position = cursor;
        let DynSolValue::FixedBytes(word, 32) = &commands[cursor] else {
            return Err("invalid command word".into());
        };
        cursor += 1;
        let flags = word[4];
        let kind = match flags & 3 {
            1 => "CALL",
            2 => "STATICCALL",
            3 => "CALL with native value",
            _ => {
                return Err(
                    "delegatecall/zero call type is not supported by the pinned Enso VM".into(),
                );
            }
        };
        let mut indices = [0xff; 32];
        let mut end = if flags & 0x40 != 0 {
            let Some(DynSolValue::FixedBytes(extended, 32)) = commands.get(cursor) else {
                return Err("extended command is missing its indices word".into());
            };
            indices.copy_from_slice(extended.as_slice());
            cursor += 1;
            32
        } else {
            indices[..6].copy_from_slice(&word[5..11]);
            6
        };
        let value_arg = if flags & 3 == 3 {
            Some(slot(&state, indices[0])?)
        } else {
            None
        };
        let value = match &value_arg {
            Some(arg) => match &arg.data {
                Some(bytes) if bytes.len() == 32 => Some(U256::from_be_slice(bytes)),
                Some(_) => return Err("call value state is not 32 bytes".into()),
                None => None,
            },
            None => Some(U256::ZERO),
        };
        let native_value = value
            .map(|value| format!("{value} raw native units"))
            .unwrap_or_else(|| value_arg.as_ref().unwrap().description.clone());
        if value_arg.is_some() {
            indices.copy_within(1.., 0);
            indices[31] = 0;
            end -= 1;
        }
        let mut offset = 0;
        let (args, calldata) = if flags & 0x20 != 0 {
            let index = *indices.get(offset).ok_or("raw calldata index is missing")?;
            let arg = slot(&state, index)?;
            let data = arg.data.clone();
            (vec![format!("raw calldata from {}", arg.description)], data)
        } else {
            let args = arguments(&indices, &mut offset, end, &state, false, 0, &mut 0)?;
            let data = encode(&args)?.map(|data| [&word[..4], &data].concat());
            (args.into_iter().map(|a| a.description).collect(), data)
        };
        let selector = calldata
            .as_ref()
            .map(|data| &data[..data.len().min(4)])
            .unwrap_or(&word[..4]);
        let output_index = word[11];
        let output = if output_index == 0xff {
            "discard return data".into()
        } else if flags & 0x80 == 0 && output_index == 0xfe {
            state = None;
            "replace entire state with returned bytes[]".into()
        } else {
            let index = usize::from(output_index & 0x7f);
            if let Some(state) = &mut state {
                let target = state
                    .get_mut(index)
                    .ok_or("output state index is out of bounds")?;
                *target = Slot::Result(format!("command word {position} return"));
            }
            format!(
                "write {}return to state[{index}]",
                if flags & 0x80 != 0 {
                    "tuple "
                } else if output_index & 0x80 != 0 {
                    "dynamic "
                } else {
                    "32-byte "
                }
            )
        };
        program.steps.push(Step {
            command_word: position,
            call_type: kind,
            target: Address::from_slice(&word[12..]),
            selector: format!("0x{}", hex::encode(selector)),
            arguments: args,
            native_value,
            output,
            value,
            reconstructed_calldata: calldata
                .as_ref()
                .map(|data| format!("0x{}", hex::encode(data))),
            calldata,
            reading: None,
            unread_reason: None,
        });
    }
    Ok(program)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shortcut(commands: &[[u8; 32]], state: Vec<Vec<u8>>) -> Vec<u8> {
        crate::parse_function(SIGNATURE)
            .unwrap()
            .abi_encode_input(&[
                DynSolValue::FixedBytes(Default::default(), 32),
                DynSolValue::FixedBytes(Default::default(), 32),
                DynSolValue::Array(
                    commands
                        .iter()
                        .map(|word| DynSolValue::FixedBytes((*word).into(), 32))
                        .collect(),
                ),
                DynSolValue::Array(state.into_iter().map(DynSolValue::Bytes).collect()),
            ])
            .unwrap()
    }

    fn command(flags: u8, inputs: &[u8], output: u8) -> [u8; 32] {
        let mut word = [0u8; 32];
        word[..4].copy_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
        word[4] = flags;
        word[5..11].fill(0xff);
        word[5..5 + inputs.len()].copy_from_slice(inputs);
        word[11] = output;
        word[12..].fill(0x11);
        word
    }

    #[test]
    fn constants_reconstruct_but_return_values_never_reuse_initial_state() {
        let words = [command(1, &[0, 1], 1), command(1, &[0, 1], 0xff)];
        let state = vec![
            U256::from(42).to_be_bytes::<32>().to_vec(),
            U256::from(7).to_be_bytes::<32>().to_vec(),
        ];
        let program = decode(&shortcut(&words, state.clone())).unwrap();
        assert_eq!(
            program.steps[0].calldata.as_deref(),
            Some([&words[0][..4], &state[0], &state[1]].concat()).as_deref()
        );
        assert!(program.steps[1].calldata.is_none());
        assert!(program.steps[1].arguments[1].contains("return"));
        let words = [command(1, &[], 0xfe), command(1, &[0], 0xff)];
        assert!(
            decode(&shortcut(&words, state)).unwrap().steps[1]
                .calldata
                .is_none()
        );
    }

    #[test]
    fn raw_value_and_extended_commands_follow_the_vm_layout() {
        let raw = vec![0xde, 0xad, 0xbe, 0xef, 1];
        let mut indices = [0xff; 32];
        indices[..2].copy_from_slice(&[0, 1]);
        let program = decode(&shortcut(
            &[command(0x63, &[], 0xff), indices],
            vec![U256::from(9).to_be_bytes::<32>().to_vec(), raw.clone()],
        ))
        .unwrap();
        assert_eq!(program.steps[0].value, Some(U256::from(9)));
        assert_eq!(program.steps[0].calldata, Some(raw));
        assert_eq!(program.steps[0].selector, "0xdeadbeef");
        assert!(decode(&shortcut(&[command(0x41, &[], 0xff)], vec![])).is_err());
        assert!(decode(&shortcut(&[command(0, &[], 0xff)], vec![])).is_err());
    }

    #[test]
    fn whole_state_dynamic_bytes_and_nested_array_match_abi() {
        let state = vec![
            U256::from(1).to_be_bytes::<32>().to_vec(),
            U256::from(5).to_be_bytes::<32>().to_vec(),
        ];
        let program = decode(&shortcut(&[command(1, &[0xfe], 0xff)], state.clone())).unwrap();
        let expected = DynSolValue::Array(state.iter().cloned().map(DynSolValue::Bytes).collect())
            .abi_encode();
        assert_eq!(&program.steps[0].calldata.as_ref().unwrap()[4..], expected);
        let program = decode(&shortcut(&[command(1, &[0xfd, 0, 1, 0xfb], 0xff)], state)).unwrap();
        let expected = DynSolValue::Array(vec![DynSolValue::Uint(U256::from(5), 256)]).abi_encode();
        assert_eq!(&program.steps[0].calldata.as_ref().unwrap()[4..], expected);
        let dynamic = DynSolValue::Bytes(vec![1, 2, 3]).abi_encode()[32..].to_vec();
        let program = decode(&shortcut(&[command(1, &[0x80], 0xff)], vec![dynamic])).unwrap();
        assert_eq!(
            &program.steps[0].calldata.as_ref().unwrap()[4..],
            DynSolValue::Bytes(vec![1, 2, 3]).abi_encode()
        );
    }

    #[test]
    fn malformed_state_indices_and_abi_are_rejected() {
        for (inputs, state) in [
            (vec![0], vec![vec![0; 31]]),
            (vec![0x80], vec![vec![]]),
            (vec![1], vec![vec![0; 32]]),
            (vec![0xfc, 0], vec![vec![0; 32]]),
            (vec![0xfc, 0xfe, 0xfb], vec![]),
        ] {
            assert!(decode(&shortcut(&[command(1, &inputs, 0xff)], state)).is_err());
        }
        let mut data = shortcut(&[], vec![]);
        data.push(0);
        assert!(decode(&data).is_err());
        assert!(decode(&shortcut(&[command(1, &[], 0xff); 65], vec![])).is_err());
        let args = [
            Argument {
                description: String::new(),
                data: None,
                dynamic: false,
            },
            Argument {
                description: String::new(),
                data: Some(vec![0; 31]),
                dynamic: false,
            },
        ];
        assert!(encode(&args).is_err());
    }
}
