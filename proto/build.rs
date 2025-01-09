fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        // the trait `Deserialize<'_>` is not implemented for `prost_types::Any`
        .field_attribute(
            "Contract.parameter",
            "#[serde(default, skip_deserializing, skip_serializing)]",
        )
        // .extern_path("./protocol", "::")
        .out_dir("./src")
        .compile_protos(
            &[
                "protocol/core/Tron.proto",
                "protocol/core/Discover.proto",
                "protocol/core/contract/exchange_contract.proto",
                "protocol/core/contract/market_contract.proto",
                "protocol/core/contract/account_contract.proto",
                "protocol/core/contract/asset_issue_contract.proto",
                "protocol/core/contract/shield_contract.proto",
                "protocol/core/contract/smart_contract.proto",
                "protocol/core/contract/storage_contract.proto",
                "protocol/core/contract/proposal_contract.proto",
                "protocol/core/contract/vote_asset_contract.proto",
                "protocol/core/contract/witness_contract.proto",
                "protocol/core/contract/balance_contract.proto",
                "protocol/core/contract/common.proto",
                "protocol/core/TronInventoryItems.proto",
                "protocol/api/api.proto",
            ],
            &["protocol", "include"],
        )?;

    Ok(())
}
