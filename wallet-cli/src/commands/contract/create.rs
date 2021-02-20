use clap::ArgMatches;
use hex::{FromHex, ToHex};
use keys::Address;
use proto::core::{
    CreateSmartContract, SmartContract, SmartContract_ABI as Abi, SmartContract_ABI_Entry_EntryType as AbiEntryType,
};
use std::convert::TryFrom;
use std::fs;
use std::path::Path;

use crate::error::Error;
use crate::utils::abi;
use crate::utils::trx;

pub fn main(matches: &ArgMatches) -> Result<(), Error> {
    if matches.is_present("libraries") {
        eprintln!("For now, library addresses should be filled by hand.");
        return Err(Error::Runtime("--libraries unimplemented"));
    }

    let owner_address: Address = matches.value_of("OWNER").expect("required in cli.yml; qed").parse()?;
    let abi = load_abi_from_param(matches.value_of("abi").expect("has default in cli.yml; qed"))?;
    let mut bytecode: Vec<u8> = load_code_from_param(matches.value_of("code").expect("required in cli.yml; qed"))?;

    let types = abi
        .get_entrys()
        .iter()
        .find(|entry| entry.get_field_type() == AbiEntryType::Constructor)
        .map(|entry| {
            entry
                .get_inputs()
                .iter()
                .map(|param| param.get_field_type())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut data = match (matches.values_of("ARGS"), matches.value_of("data")) {
        (Some(args), None) => {
            // Fix tron base58checked addresses, remove 0x41
            let values = args
                .zip(types.iter())
                .map(|(arg, ty)| {
                    if ty == &"address" {
                        arg.parse::<Address>()
                            .map(|addr| addr.as_tvm_bytes().encode_hex::<String>())
                            .map_err(Error::from)
                    } else {
                        Ok(arg.to_owned())
                    }
                })
                .collect::<Result<Vec<_>, Error>>()?;
            abi::encode_params(&types, &values)?
        }
        (None, Some(data_hex)) => Vec::from_hex(data_hex)?,
        (None, None) => vec![],
        (_, _) => unreachable!("set conflicts in cli.yml; qed"),
    };

    bytecode.append(&mut data);

    let mut new_contract = SmartContract::new();
    new_contract.set_bytecode(bytecode);
    new_contract.set_abi(abi);

    new_contract.set_origin_address(owner_address.as_bytes().to_owned());
    if let Some(name) = matches.value_of("name") {
        new_contract.set_name(name.to_owned());
    }

    let percent = matches
        .value_of("user-resource-percent")
        .expect("has default in cli.yml; qed")
        .parse()?;
    new_contract.set_consume_user_resource_percent(percent);

    if let Some(val) = matches.value_of("energy-limit") {
        new_contract.set_origin_energy_limit(val.parse()?);
    }

    let mut create_contract = CreateSmartContract::new();
    create_contract.set_owner_address(owner_address.as_bytes().to_owned());

    if let Some(value) = matches.value_of("value") {
        new_contract.set_call_value(trx::parse_amount_with_surfix(value, "TRX", 6)?);
    }
    create_contract.set_new_contract(new_contract);

    if let Some(token_id) = matches.value_of("token-id") {
        let value = matches.value_of("token-value").expect("constraint in cli.yml; qed");
        create_contract.set_token_id(token_id.parse()?);
        create_contract.set_call_token_value(trx::parse_amount(value)?);
    }

    let mut handler = trx::TransactionHandler::handle(create_contract, matches);
    handler.map_raw_transaction(|raw| raw.set_fee_limit(1_000_000));
    handler.run()?;
    handler.watch(|info| {
        println!(
            "! Created Contract Address(Base58Check) = {}",
            Address::try_from(info.get_contract_address())?
        );
        Ok(())
    })
}

fn load_abi_from_param(param: &str) -> Result<Abi, Error> {
    match param {
        fname if Path::new(fname).exists() => {
            let raw_json = fs::read_to_string(Path::new(fname))?;
            Ok(abi::json_to_abi(&serde_json::from_str(&raw_json)?))
        }
        fname if fname.starts_with('@') => {
            let raw_json = fs::read_to_string(Path::new(&fname[1..]))?;
            Ok(abi::json_to_abi(&serde_json::from_str(&raw_json)?))
        }
        raw_json if raw_json.trim_start().starts_with("[") => Ok(abi::json_to_abi(&serde_json::from_str(&raw_json)?)),
        _ => Err(Error::Runtime("can not determine ABI format")),
    }
}

fn load_code_from_param(param: &str) -> Result<Vec<u8>, Error> {
    let maybe_fname = if Path::new(param).exists() {
        Some(param)
    } else if param.starts_with('@') {
        Some(&param[1..])
    } else {
        None
    };
    match maybe_fname {
        Some(fname) => {
            let code_hex = fs::read_to_string(fname)?;
            hex::decode(
                code_hex
                    .chars()
                    .filter(|c| !c.is_ascii_whitespace())
                    .collect::<String>(),
            )
            .map_err(|_| Error::Runtime("can not parse code file as hex"))
        }
        None => hex::decode(param).map_err(|_| Error::Runtime("can not determine code format")),
    }
}
