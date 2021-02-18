use crate::Error;
use clap::ArgMatches;
use keys::{Address, KeyPair};
use serde_json::json;

pub fn main(matches: &ArgMatches<'_>) -> Result<(), Error> {
    match matches.subcommand() {
        ("generate", _) => generate_key(),
        ("inspect", Some(arg_matches)) => inspect_key(arg_matches),
        // ("generate-genesis-key", _) => unimplemented!(),
        _ => {
            eprintln!("{}", matches.usage());
            Ok(())
        }
    }
}

fn generate_key() -> Result<(), Error> {
    let kp = KeyPair::generate();
    let address = kp.address();

    let json = json!({
        "public_key": kp.public().to_string(),
        "private_key": kp.private().to_string(),
        "address_base58check": address.to_string(),
        "address_hex": address.to_hex_address(),
        "address_eth": address.to_eth_address(),
    });

    println!("{}", serde_json::to_string_pretty(&json)?);
    Ok(())
}

fn inspect_key(matches: &ArgMatches<'_>) -> Result<(), Error> {
    let mut json = json!({});
    let address = match matches.value_of("ADDRESS") {
        Some(raw_addr) => raw_addr.parse()?,
        _ if matches.is_present("private") => {
            let priv_key: keys::Private = matches.value_of("private").unwrap().parse()?;
            let kp = KeyPair::from_private(priv_key)?;
            json["public_key"] = json!(kp.public().to_string());
            json["private_key"] = json!(kp.private().to_string());
            kp.address()
        }
        _ if matches.is_present("public") => {
            let pub_key: keys::Public = matches.value_of("public").unwrap().parse()?;
            json["public_key"] = json!(pub_key.to_string());
            Address::from_public(&pub_key)
        }
        _ => {
            eprintln!("{}", matches.usage());
            return Ok(());
        }
    };

    json["address_base58check"] = json!(address.to_string());
    json["address_hex"] = json!(address.to_hex_address());
    json["address_eth"] = json!(address.to_eth_address());

    println!("{}", serde_json::to_string_pretty(&json)?);

    Ok(())
}
