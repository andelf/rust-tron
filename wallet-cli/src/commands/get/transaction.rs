use std::convert::TryFrom;
use std::str;

use chrono::{Local, TimeZone, Utc};
use futures::executor;
use itertools::Itertools;
use keys::Address;
use proto::api::BytesMessage;
use proto::core::{
    TransactionInfo_Log as Log, Transaction_Contract_ContractType as ContractType,
    Transaction_Result_code as ResultCode, Transaction_Result_contractResult as ContractResult,
};
use protobuf::Message;

use crate::error::Error;
use crate::utils::abi;
use crate::utils::client;
use crate::utils::crypto;
use crate::utils::jsont;
use crate::utils::trx;

pub fn get_transaction(id: &str) -> Result<(), Error> {
    let mut req = BytesMessage::new();
    req.value = parse_hex(id)?;

    let mut payload = executor::block_on(
        client::GRPC_CLIENT
            .get_transaction_by_id(Default::default(), req)
            .drop_metadata(),
    )?;

    let mut transaction = serde_json::to_value(&payload)?;
    if transaction["raw_data"].is_null() {
        return Err(Error::Runtime("transaction not found"));
    }
    jsont::fix_transaction(&mut transaction)?;
    println!("{}", serde_json::to_string_pretty(&transaction).unwrap());

    if !payload.get_raw_data().get_data().is_empty() {
        eprintln!(
            "! Data: {:?}",
            String::from_utf8_lossy(payload.get_raw_data().get_data())
        );
    }

    if payload.get_raw_data().timestamp < Utc::now().timestamp_millis() {
        eprintln!(
            "! Timestamp: {}",
            Local.timestamp(
                payload.get_raw_data().timestamp / 1_000,
                (payload.get_raw_data().timestamp % 1_000 * 1_000_000) as _
            )
        );
    } else {
        eprintln!("! Timestamp: N/A");
    }
    eprintln!(
        "! Expiration: {}",
        Local.timestamp(
            payload.get_raw_data().expiration / 1_000,
            (payload.get_raw_data().expiration % 1_000 * 1_000_000) as _
        )
    );

    let sender = trx::extract_owner_address_from_parameter(payload.get_raw_data().get_contract()[0].get_parameter())?;
    eprintln!("! Sender Address(base58check):   {}", sender);

    // eprintln!("Raw data => {}", hex::encode(payload.get_raw_data().write_to_bytes()?));

    if payload.get_raw_data().get_contract()[0].get_field_type() == ContractType::TriggerSmartContract &&
        payload.get_ret()[0].get_ret() == ResultCode::SUCESS
    {
        let contract_address = transaction["raw_data"]["contract"][0]["parameter"]["value"]["contract_address"]
            .as_str()
            .ok_or(Error::Runtime("unreachable field"))
            .and_then(|s| s.parse::<Address>().map_err(Error::from))?;
        let data = transaction["raw_data"]["contract"][0]["parameter"]["value"]["data"]
            .as_str()
            .unwrap();
        eprintln!("! Contract Address(base58check): {}", contract_address);
        eprintln!("! Contract result: {:?}", payload.get_ret()[0].get_contractRet());
        pprint_contract_call_data(&contract_address, data)?;
    }

    // NOTE: when calculating bandwidth, `Transaction.ret` must be excluded.
    payload.clear_ret();
    eprintln!(
        "! Bandwidth: {}",
        payload.compute_size() as usize + trx::MAX_RESULT_SIZE_IN_TX
    );

    Ok(())
}

pub fn get_transaction_info(id: &str) -> Result<(), Error> {
    let mut req = BytesMessage::new();
    req.value = parse_hex(id)?;

    let payload = executor::block_on(
        client::GRPC_CLIENT
            .get_transaction_info_by_id(Default::default(), req)
            .drop_metadata(),
    )?;

    if payload.get_id().is_empty() {
        return Err(Error::Runtime("transaction not found"));
    }
    let mut json = serde_json::to_value(&payload)?;
    jsont::fix_transaction_info(&mut json);

    println!("{}", serde_json::to_string_pretty(&json)?);

    eprintln!(
        "! Block Timestamp: {}",
        Local.timestamp(payload.get_blockTimeStamp() / 1_000, 0)
    );

    if payload.get_receipt().net_usage > 0 {
        eprintln!("! Free/Frozen Bandwidth Used: {}", payload.get_receipt().net_usage);
    }
    if payload.get_receipt().net_fee > 0 {
        eprintln!(
            "! Burnt for Bandwidth: {} TRX",
            payload.get_receipt().net_fee as f64 / 1_000_000.0
        );
    }
    if payload.get_receipt().net_fee == 100000 {
        eprintln!("! Might be an account creation");
    }

    if payload.get_receipt().energy_usage > 0 {
        eprintln!("! Frozen Energy Used: {}", payload.get_receipt().energy_usage);
    }
    if payload.get_receipt().energy_fee > 0 {
        eprintln!(
            "! Burnt for Energy: {} TRX",
            payload.get_receipt().energy_fee as f64 / 1_000_000.0
        );
    }
    if payload.get_receipt().origin_energy_usage > 0 {
        eprintln!(
            "! Contract Owner's Energy Used: {}",
            payload.get_receipt().origin_energy_usage
        );
    }
    if payload.get_receipt().energy_usage_total > 0 {
        eprintln!("! Total Energy: {}", payload.get_receipt().energy_usage_total);
    }

    if payload.fee > 0 {
        eprintln!("! Total Fee: {} TRX", payload.fee as f64 / 1_000_000.0);
    }

    if [ContractResult::OUT_OF_TIME, ContractResult::JVM_STACK_OVER_FLOW].contains(&payload.get_receipt().result) {
        eprintln!("!! All of Fee Limit Spent!");
    }

    if !payload.get_contract_address().is_empty() {
        eprintln!(
            "! Contract Address: {}",
            Address::try_from(payload.get_contract_address())?
        );
        eprintln!("! Contract result: {:?}", payload.get_receipt().get_result());
    }

    if payload.get_receipt().result == ContractResult::REVERT {
        if let Some(revert_msg) = payload.get_contractResult().get(0) {
            // function selecter: 4 bytes
            // memory offset of string: 32 bytes
            // length of string: 32 bytes
            // remain: the string
            if revert_msg.len() > 4 + 32 + 32 {
                eprintln!("! Revert Message: {:?}", str::from_utf8(&revert_msg[4 + 32 + 32..]))
            }
        }
    }
    if !payload.get_log().is_empty() {
        eprintln!("! Event Logs: {}", payload.get_log().len());

        let _ = pprint_contract_logs(payload.get_log());
    }

    Ok(())
}

fn pprint_contract_logs(logs: &[Log]) -> Result<(), Error> {
    use proto::core::SmartContract_ABI_Entry_EntryType as AbiEntryType;

    for (i, log) in logs.iter().enumerate() {
        let cntr_addr = Address::from_tvm_bytes(log.get_address());
        let abi_entries = trx::get_contract_abi(&cntr_addr)?;

        let entry = abi_entries
            .iter()
            .chain(abi::DEFAULT_EVENT_ABI.iter())
            .filter(|e| e.get_field_type() == AbiEntryType::Event)
            .find(|e| crypto::keccak256(abi::entry_to_method_name(&e).as_bytes()).as_ref() == log.get_topics()[0]);

        eprintln!("! Event#{} {}", i, cntr_addr);
        if let Some(entry) = entry {
            eprintln!("  {}", abi::entry_to_method_name_pretty(entry)?);

            let indexed_param_types = abi::entry_to_indexed_types(entry);
            let indexed_params = abi::decode_params(
                &indexed_param_types,
                &hex::encode(log.get_topics()[1..].iter().cloned().concat()),
            )?;

            let param_types = abi::entry_to_non_indexed_types(entry);
            let params = abi::decode_params(&param_types, &hex::encode(&log.get_data()))?;

            let mut i = 0;
            let mut j = 0;
            for arg in entry.get_inputs().iter() {
                if arg.get_indexed() {
                    eprintln!(
                        "      {} indexed {} = {}",
                        arg.get_field_type(),
                        arg.get_name(),
                        indexed_params[i]
                    );
                    i += 1;
                } else {
                    eprintln!("      {} {} = {}", arg.get_field_type(), arg.get_name(), params[j]);
                    j += 1;
                }
            }
        } else {
            eprintln!("  {}", hex::encode(&log.get_topics()[0]));
            eprintln!("  (ABI not found, cannot parse)");
        }
    }

    Ok(())
}

fn pprint_contract_call_data(contract: &Address, data: &str) -> Result<(), Error> {
    let abi = trx::get_contract_abi(contract)?;
    let fnhash = hex::decode(&data[..8])?;
    abi.iter()
        .find(|entry| abi::fnhash(&abi::entry_to_method_name(entry)) == fnhash[..])
        .ok_or(Error::Runtime("ABI not found, can not parse result"))
        .and_then(|entry| {
            eprintln!("! {}", abi::entry_to_method_name_pretty(entry)?);
            eprintln!(
                "!          {} [{}]",
                abi::entry_to_method_name(entry),
                hex::encode(fnhash)
            );
            let types = abi::entry_to_input_types(&entry);
            let params = abi::decode_params(&types, &data[8..])?;
            if !types.is_empty() {
                eprintln!("! Arguments:");
                for (input, param) in entry.get_inputs().iter().zip(params.iter()) {
                    eprintln!("  {}: {} = {}", input.get_name(), input.get_field_type(), param);
                }
            }
            Ok(())
        })
}

fn parse_hex(s: &str) -> Result<Vec<u8>, Error> {
    if s.starts_with("0x") {
        Ok(hex::decode(&s[2..])?)
    } else {
        Ok(hex::decode(s)?)
    }
}
