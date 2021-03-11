use clap::ArgMatches;
use futures::executor;
use proto::api::{BytesMessage, EmptyMessage};
use serde_json::json;

use crate::error::Error;
use crate::utils::client;
use crate::utils::jsont;

fn list_nodes() -> Result<(), Error> {
    let req = EmptyMessage::new();
    let payload = executor::block_on(client::GRPC_CLIENT.list_nodes(Default::default(), req).drop_metadata())?;

    let mut nodes = serde_json::to_value(&payload)?;
    nodes["nodes"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .map(|node| {
            node["address"]["host"] = json!(jsont::bytes_to_string(&node["address"]["host"]));
        })
        .last();
    println!("{}", serde_json::to_string_pretty(&nodes["nodes"])?);
    Ok(())
}

fn list_witnesses() -> Result<(), Error> {
    let req = EmptyMessage::new();
    let payload = executor::block_on(
        client::GRPC_CLIENT
            .list_witnesses(Default::default(), req)
            .drop_metadata(),
    )?;
    let mut witnesses = serde_json::to_value(&payload)?;
    witnesses["witnesses"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .map(|witness| {
            witness["address"] = json!(jsont::bytes_to_hex_string(&witness["address"]));
        })
        .last();
    println!("{}", serde_json::to_string_pretty(&witnesses["witnesses"])?);

    let mut active_witnesses = payload
        .get_witnesses()
        .iter()
        .filter(|wit| wit.get_isJobs())
        .collect::<Vec<_>>();
    active_witnesses.sort_by_key(|wit| -wit.get_voteCount());
    for wit in &active_witnesses {
        let mut req = BytesMessage::new();
        req.set_value(wit.get_address().to_owned());

        let kept_percent = executor::block_on(
            client::GRPC_CLIENT
                .get_brokerage_info(Default::default(), req)
                .drop_metadata(),
        )?
        .get_num();
        let share_percent = 100 - kept_percent;
        eprintln!(
            "! {}\t{}\t{}%\t{}",
            keys::b58encode_check(wit.get_address()),
            wit.get_voteCount(),
            share_percent,
            wit.get_url(),
        );
    }
    Ok(())
}

fn list_assets() -> Result<(), Error> {
    let req = EmptyMessage::new();
    let payload = executor::block_on(
        client::GRPC_CLIENT
            .get_asset_issue_list(Default::default(), req)
            .drop_metadata(),
    )?;
    let mut assets = serde_json::to_value(&payload)?;

    assets["assetIssue"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .map(jsont::fix_asset_issue_contract)
        .last();

    println!("{}", serde_json::to_string_pretty(&assets["assetIssue"])?);
    Ok(())
}

pub fn list_proposals() -> Result<(), Error> {
    let mut payload = executor::block_on(
        client::GRPC_CLIENT
            .list_proposals(Default::default(), EmptyMessage::new())
            .drop_metadata(),
    )?;
    let reversed = payload.take_proposals().into_iter().rev().collect();
    payload.set_proposals(reversed);
    let mut proposals = serde_json::to_value(&payload)?;

    let mut witnesses = executor::block_on(
        client::GRPC_CLIENT
            .list_witnesses(Default::default(), EmptyMessage::new())
            .drop_metadata(),
    )?;
    let mut witnesses = witnesses.take_witnesses();
    witnesses.sort_by_key(|wit| wit.get_voteCount());
    let active_wit_addrs: Vec<_> = witnesses.iter().rev().map(|wit| wit.get_address()).take(27).collect();

    proposals["proposals"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .map(|proposal| {
            proposal["proposer_address"] = {
                if active_wit_addrs.contains(&&jsont::bytes_to_bytes(&proposal["proposer_address"])[..]) {
                    json!(format!(
                        "{} - SR",
                        keys::b58encode_check(jsont::bytes_to_bytes(&proposal["proposer_address"]))
                    ))
                } else {
                    json!(format!(
                        "{} - SRP",
                        keys::b58encode_check(jsont::bytes_to_bytes(&proposal["proposer_address"]))
                    ))
                }
            };
            proposal["approvals"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .map(|val| {
                    *val = if active_wit_addrs.contains(&&jsont::bytes_to_bytes(val)[..]) {
                        json!(format!("{} - SR", keys::b58encode_check(jsont::bytes_to_bytes(val))))
                    } else {
                        json!(format!("{} - SRP", keys::b58encode_check(jsont::bytes_to_bytes(&val))))
                    };
                })
                .last();
        })
        .last();
    println!("{}", serde_json::to_string_pretty(&proposals["proposals"])?);

    Ok(())
}

pub fn list_parameters() -> Result<(), Error> {
    let payload = executor::block_on(
        client::GRPC_CLIENT
            .get_chain_parameters(Default::default(), EmptyMessage::new())
            .drop_metadata(),
    )?;
    let parameters = serde_json::to_value(&payload)?;
    println!("{}", serde_json::to_string_pretty(&parameters["chainParameter"])?);
    Ok(())
}

pub fn list_exchanges() -> Result<(), Error> {
    let payload = executor::block_on(
        client::GRPC_CLIENT
            .list_exchanges(Default::default(), EmptyMessage::new())
            .drop_metadata(),
    )?;
    let mut exchanges = serde_json::to_value(&payload)?;
    exchanges["exchanges"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .map(|ex| {
            ex["creator_address"] = json!(jsont::bytes_to_hex_string(&ex["creator_address"]));
            ex["first_token_id"] = json!(jsont::bytes_to_string(&ex["first_token_id"]));
            ex["second_token_id"] = json!(jsont::bytes_to_string(&ex["second_token_id"]));
        })
        .last();
    println!("{}", serde_json::to_string_pretty(&exchanges["exchanges"])?);
    Ok(())
}

pub fn main(matches: &ArgMatches) -> Result<(), Error> {
    match matches.subcommand() {
        ("node", _) => list_nodes(),
        ("witness", _) => list_witnesses(),
        ("asset", _) => list_assets(),
        ("proposal", _) => list_proposals(),
        ("parameter", _) => list_parameters(),
        ("exchange", _) => list_exchanges(),
        _ => {
            eprintln!("{}", matches.usage());
            Err(Error::Runtime("error parsing command line"))
        }
    }
}
