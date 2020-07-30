use clap::ArgMatches;
use futures::executor;
use futures::FutureExt;
use keys::{Address, Private};
use proto::api::NumberMessage;
use proto::core::{Transaction, Transaction_Contract as Contract, Transaction_raw as TransactionRaw, TransferContract};
use protobuf::Message;
use std::fs;

use crate::error::Error;
use crate::utils::client;
use crate::utils::crypto;
use crate::utils::trx;
use crate::utils::trx::{parse_amount_with_surfix, timestamp_millis, ContractPbExt};
use crate::CHAIN_ID;

pub fn main<'a>(matches: &'a ArgMatches<'a>) -> Result<(), Error> {
    let sender = matches
        .value_of("SENDER")
        .and_then(|s| s.parse::<Address>().ok())
        .ok_or(Error::Runtime("wrong sender address format"))?;
    let batch = matches.value_of("BATCH").expect("required in cli.yml; qed");

    let content = fs::read_to_string(batch)?;

    let mut transfers = vec![];
    for line in content.lines() {
        let segs: Vec<_> = line.split_ascii_whitespace().collect();
        let mut transfer = TransferContract::new();
        // raw_txn
        transfer.set_owner_address(sender.as_bytes().to_vec());
        transfer.set_to_address(segs[0].parse::<Address>()?.as_bytes().to_vec());
        transfer.set_amount(trx::parse_amount_with_surfix(segs[1], "TRX", 6)?);
        transfers.push(transfer);
    }

    BatchTransactionHandler::prepare(transfers, matches).run()
}

pub struct BatchTransactionHandler<'a, C> {
    contracts: Vec<C>,
    arg_matches: &'a ArgMatches<'a>,
}

impl<'a, C: ContractPbExt> BatchTransactionHandler<'a, C> {
    pub fn prepare(contracts: Vec<C>, matches: &'a ArgMatches<'a>) -> Self {
        BatchTransactionHandler {
            contracts,
            arg_matches: matches,
        }
    }

    pub fn run(&self) -> Result<(), Error> {
        let matches = self.arg_matches;

        let ref_block = match matches.value_of("ref-block") {
            Some(num) => {
                let mut req = NumberMessage::new();
                req.set_num(num.parse()?);
                let block = executor::block_on(
                    client::GRPC_CLIENT
                        .get_block_by_num2(Default::default(), req)
                        .drop_metadata(),
                )?;
                block
            }
            None => {
                let block = executor::block_on(
                    client::GRPC_CLIENT
                        .get_now_block2(Default::default(), Default::default())
                        .drop_metadata(),
                )?;
                block
            }
        };
        let ref_block_number = ref_block.get_block_header().get_raw_data().number;
        let ref_block_bytes = vec![
            ((ref_block_number & 0xff00) >> 8) as u8,
            (ref_block_number & 0xff) as u8,
        ];
        let ref_block_hash = &ref_block.blockid[8..16];
        eprintln!("! Use ref block {}", ref_block_number);

        let mut acc_timestamp = timestamp_millis();

        let txns = self
            .contracts
            .iter()
            .map(|inner| {
                let mut raw_txn = to_partial_raw_transaction(inner, matches)?;
                raw_txn.set_ref_block_bytes(ref_block_bytes.clone());
                raw_txn.set_ref_block_hash(ref_block_hash.to_vec());
                raw_txn.set_timestamp(acc_timestamp);
                acc_timestamp += 1;
                eprint!(".");
                to_signed_transaction(raw_txn, matches)
            })
            .collect::<Result<Vec<_>, Error>>()?;

        eprintln!("\n! Signed {} transactions", txns.len());

        let mut futs = vec![];
        for (txid, txn) in txns {
            futs.push(
                client::GRPC_CLIENT
                    .broadcast_transaction(Default::default(), txn)
                    .drop_metadata()
                    .map(move |res| (txid, res.map(|ret| ret.result))),
            );
        }
        let payload = executor::block_on(futures::future::join_all(futs));
        for (txid, result) in payload {
            println!("{} => {:?}", hex::encode(txid), result);
        }
        Ok(())
    }
}

fn to_partial_raw_transaction<C: ContractPbExt>(inner: &C, matches: &ArgMatches) -> Result<TransactionRaw, Error> {
    let any = inner.as_google_any()?;

    let mut contract = Contract::new();
    contract.set_field_type(inner.contract_type());
    contract.set_parameter(any);
    if let Some(val) = matches.value_of("permission-id") {
        contract.set_Permission_id(val.parse()?);
    }

    let mut raw = TransactionRaw::new();
    raw.set_contract(vec![contract].into());

    if let Some(memo) = matches.value_of("memo") {
        raw.set_data(memo.as_bytes().to_owned())
    }

    if let Some(fee_limit_amount) = matches.value_of("fee-limit") {
        let limit = parse_amount_with_surfix(fee_limit_amount, "TRX", 6)?;
        raw.set_fee_limit(limit);
    }

    // Use 10min as default
    let expiration = matches.value_of("expiration").unwrap_or("600").parse::<i64>()?;
    raw.set_expiration(timestamp_millis() + 1000 * expiration);

    Ok(raw)
}

fn to_signed_transaction(raw: TransactionRaw, matches: &ArgMatches) -> Result<([u8; 32], Transaction), Error> {
    use crate::commands::wallet::sign_digest;

    // signature
    let txid = crypto::sha256(&raw.write_to_bytes()?);

    // special signature routine for Sun-Network
    let digest = if let Some(chain_id) = unsafe { CHAIN_ID } {
        let mut raw = (&txid[..]).to_owned();
        raw.extend(hex::decode(chain_id)?);
        crypto::sha256(&raw)
    } else {
        txid
    };
    let mut signatures: Vec<Vec<u8>> = Vec::new();

    let signature = if let Some(raw_key) = matches.value_of("private-key") {
        let priv_key = raw_key.parse::<Private>()?;
        priv_key.sign_digest(&digest)?[..].to_owned()
    } else {
        let owner_address = matches
            .value_of("account")
            .and_then(|addr| addr.parse().ok())
            .or_else(|| trx::extract_owner_address_from_parameter(raw.contract[0].get_parameter()).ok())
            .ok_or(Error::Runtime("can not determine owner address for signing"))?;
        sign_digest(&digest, &owner_address)?
    };
    signatures.push(signature);

    let mut txn = Transaction::new();
    txn.set_raw_data(raw);
    txn.set_signature(signatures.into());

    Ok((txid, txn))
}
