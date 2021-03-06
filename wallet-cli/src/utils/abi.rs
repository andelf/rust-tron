//! ABI related utilities

use ethabi::param_type::{ParamType, Reader};
use ethabi::token::{LenientTokenizer, StrictTokenizer, Token, Tokenizer};
use ethabi::{decode, encode};
use hex::{FromHex, ToHex};
use keys::Address;
use lazy_static::lazy_static;
use proto::core::{
    SmartContract_ABI as Abi, SmartContract_ABI_Entry as AbiEntry, SmartContract_ABI_Entry_EntryType as AbiEntryType,
    SmartContract_ABI_Entry_Param as AbiEntryParam, SmartContract_ABI_Entry_StateMutabilityType as StateMutabilityType,
    SmartContract_ABI_Entry_StateMutabilityType as AbiEntryStateMutabilityType,
};
use std::fmt::Write as FmtWrite;

use crate::error::Error;
use crate::utils::crypto;

lazy_static! {
    pub static ref DEFAULT_EVENT_ABI: Vec<AbiEntry> = {
        let json = serde_json::from_str(include_str!("./events.abi")).unwrap();
        json_to_abi(&json).entrys.to_vec()
    };
}

#[inline]
/// Hash code of a contract method.
pub fn fnhash(fname: &str) -> [u8; 4] {
    let mut hash_code = [0u8; 4];
    (&mut hash_code[..]).copy_from_slice(&crypto::keccak256(fname.as_bytes())[..4]);
    hash_code
}

// ref: https://github.com/paritytech/ethabi/blob/master/cli/src/main.rs
pub fn encode_params(types: &[&str], values: &[String]) -> Result<Vec<u8>, Error> {
    assert_eq!(types.len(), values.len());

    let types: Vec<ParamType> = types
        .iter()
        .map(|&s| {
            if s == "trcToken" {
                Reader::read("uint256")
            } else {
                Reader::read(s)
            }
        })
        .collect::<Result<_, _>>()?;
    let params: Vec<_> = types.into_iter().zip(values.iter().map(|v| v as &str)).collect();

    let tokens = parse_tokens(&params, true)?;
    let result = encode(&tokens);

    Ok(result.to_vec())
}

pub fn decode_params(types: &[&str], data: &str) -> Result<Vec<String>, Error> {
    let types: Vec<ParamType> = types
        .iter()
        .map(|&s| {
            if s == "trcToken" {
                Reader::read("uint256")
            } else {
                Reader::read(s)
            }
        })
        .collect::<Result<_, _>>()?;
    let data: Vec<u8> = Vec::from_hex(data)?;
    let tokens = decode(&types, &data)?;

    assert_eq!(types.len(), tokens.len());

    Ok(tokens.iter().map(pformat_abi_token).collect())
}

fn parse_tokens(params: &[(ParamType, &str)], lenient: bool) -> Result<Vec<Token>, Error> {
    params
        .iter()
        .map(|&(ref param, value)| match lenient {
            true => LenientTokenizer::tokenize(param, value),
            false => StrictTokenizer::tokenize(param, value),
        })
        .collect::<Result<_, _>>()
        .map_err(From::from)
}

fn pformat_abi_token(tok: &Token) -> String {
    match tok {
        Token::Address(raw) => Address::from_tvm_bytes(raw.as_ref()).to_string(),
        Token::String(s) => format!("{:?}", s),
        Token::Uint(val) => val.to_string(),
        Token::Bool(val) => val.to_string(),
        Token::Array(val) | Token::FixedArray(val) => {
            format!("[{}]", val.iter().map(pformat_abi_token).collect::<Vec<_>>().join(", "))
        }
        Token::Bytes(val) => val.encode_hex::<String>(),
        Token::FixedBytes(val) => hex::encode(&val),
        Token::Tuple(_) => "tuple(...)".into(),
        ref t => format!("{:?}", t),
    }
}

pub fn entry_to_method_name(entry: &AbiEntry) -> String {
    format!(
        "{}({})",
        entry.get_name(),
        entry
            .get_inputs()
            .iter()
            .map(|arg| arg.get_field_type().to_owned())
            .collect::<Vec<_>>()
            .join(",")
    )
}

pub fn entry_to_method_name_pretty(entry: &AbiEntry) -> Result<String, Error> {
    let mut pretty = match entry.get_field_type() {
        AbiEntryType::Function | AbiEntryType::Fallback => "function".to_owned(),
        AbiEntryType::Event => "event".to_owned(),
        AbiEntryType::Constructor => "constructor".to_owned(),
        _ => "".to_owned(),
    };
    if entry.get_field_type() != AbiEntryType::Fallback {
        write!(pretty, " {:}", entry.get_name())?;
    }
    write!(
        pretty,
        "({})",
        entry
            .get_inputs()
            .iter()
            .map(|arg| if arg.get_name().is_empty() {
                arg.get_field_type().to_owned()
            } else if arg.get_indexed() {
                // used in event
                format!("{:} indexed {:}", arg.get_field_type(), arg.get_name())
            } else {
                format!("{:} {:}", arg.get_field_type(), arg.get_name())
            })
            .collect::<Vec<_>>()
            .join(", ")
    )?;
    if entry.payable {
        write!(pretty, " payable")?;
    }
    if entry.get_stateMutability() == StateMutabilityType::View {
        write!(pretty, " view")?;
    }

    if !entry.get_outputs().is_empty() {
        write!(
            pretty,
            " returns ({})",
            entry
                .get_outputs()
                .iter()
                .map(|arg| arg.get_field_type().to_owned())
                .collect::<Vec<_>>()
                .join(", "),
        )?;
    }
    Ok(pretty)
}

pub fn entry_to_output_types(entry: &AbiEntry) -> Vec<&str> {
    entry
        .get_outputs()
        .iter()
        .map(|arg| arg.get_field_type())
        .collect::<Vec<_>>()
}

pub fn entry_to_input_types(entry: &AbiEntry) -> Vec<&str> {
    entry
        .get_inputs()
        .iter()
        .map(|arg| arg.get_field_type())
        .collect::<Vec<_>>()
}

pub fn entry_to_indexed_types(entry: &AbiEntry) -> Vec<&str> {
    entry
        .get_inputs()
        .iter()
        .filter(|arg| arg.get_indexed())
        .map(|arg| arg.get_field_type())
        .collect::<Vec<_>>()
}

pub fn entry_to_non_indexed_types(entry: &AbiEntry) -> Vec<&str> {
    entry
        .get_inputs()
        .iter()
        .filter(|arg| !arg.get_indexed())
        .map(|arg| arg.get_field_type())
        .collect::<Vec<_>>()
}

#[inline]
fn translate_state_mutablility(val: &serde_json::Value) -> AbiEntryStateMutabilityType {
    match val.as_str().unwrap_or_default().to_ascii_lowercase().as_ref() {
        "view" => AbiEntryStateMutabilityType::View,
        "nonpayable" => AbiEntryStateMutabilityType::Nonpayable,
        "payable" => AbiEntryStateMutabilityType::Payable,
        "pure" => AbiEntryStateMutabilityType::Pure,
        "" => AbiEntryStateMutabilityType::UnknownMutabilityType,
        x => {
            println!("unknown => {:?}", x);
            unimplemented!()
        }
    }
}

#[inline]
fn translate_abi_type(val: &serde_json::Value) -> AbiEntryType {
    match val.as_str().unwrap_or("").to_ascii_lowercase().as_ref() {
        "function" => AbiEntryType::Function,
        "event" => AbiEntryType::Event,
        "constructor" => AbiEntryType::Constructor,
        "fallback" => AbiEntryType::Fallback,
        _ => unimplemented!(),
    }
}

#[inline]
fn translate_abi_entry_params(val: &serde_json::Value) -> Vec<AbiEntryParam> {
    val.as_array()
        .map(|arr| {
            arr.iter()
                .map(|param| AbiEntryParam {
                    indexed: param["indexed"].as_bool().unwrap_or(false),
                    name: param["name"].as_str().unwrap_or("").to_owned(),
                    field_type: param["type"].as_str().unwrap_or("").to_owned(),
                    ..Default::default()
                })
                .collect()
        })
        .unwrap_or_default()
}

pub fn json_to_abi(json: &serde_json::Value) -> Abi {
    let entries: Vec<AbiEntry> = json
        .as_array()
        .unwrap()
        .iter()
        .map(|abi| {
            let mut entry = AbiEntry::new();
            entry.set_anonymous(abi["anonymous"].as_bool().unwrap_or(false));
            entry.set_constant(abi["constant"].as_bool().unwrap_or(false));
            entry.set_name(abi["name"].as_str().unwrap_or("").to_owned());
            entry.set_payable(abi["payable"].as_bool().unwrap_or(false));
            entry.set_stateMutability(translate_state_mutablility(&abi["stateMutability"]));
            entry.set_field_type(translate_abi_type(&abi["type"]));

            entry.set_inputs(translate_abi_entry_params(&abi["inputs"]).into());
            entry.set_outputs(translate_abi_entry_params(&abi["outputs"]).into());

            entry
        })
        .collect();

    Abi {
        entrys: entries.into(),
        ..Default::default()
    }
}
