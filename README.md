# rust-tron

Rust implementation of the Tron gRPC Client, and a command line wallet.

This project is under active development.

- [x] wallet-cli (the full feature wallet/rpc client)
  - [x] walletd (the wallet daemon)
## TODOs

- [x] wallet-cli
  - [ ] shielded transaction
    - [x] demo works
    - [ ] shielded notes management
    - [ ] real subcommand

## quickstart

```console
> # install rust-nightly
> curl https://sh.rustup.rs -sSf | sh -s -- --default-toolchain nightly
> rustup component add rustfmt

> # install protoc
> brew install protobuf  # macOS
> sudo pacman -S protobuf  # ArchLinux
> sudo apt install protobuf-compiler libprotobuf-dev # Ubuntu / Debian

> # get code
> git clone --recurse-submodules https://github.com/andelf/rust-tron.git

> # compile tools
> cd ./rust-tron/
> cargo build --all

> # time to rock !!!
> ./target/debug/wallet-cli --help

> # or use testnet toolset
> ./nile-wallet-cli.sh
```

## wallet-cli

A command-line tool which let developers interact Tron Protocol as well as deploy, test smart contracts.

> NOTE: Always use ``--help`` to get hint about how to use the command.

### All System Contracts Support and corresponding wallet-cli commands

- Account
  - AccountUpdateContract: `set account_name`
  - AccountPermissionUpdateContract: `set account_permission`
  - FreezeBalanceContract: `system freeze`
  - UnfreezeBalanceContract: `system unfreeze`
- Transfer: `transfer`
- TRC10 Asset
  - TransferAssetContract: `asset transfer`
  - AssetIssueContract: `asset issue`
  - UpdateAssetContract: `asset update`
  - ParticipateAssetIssueContract: `asset participate`
  - UnfreezeAssetContract: `asset unfreeze`
- SmartContract
  - CreateSmartContract: `contract create`
  - TriggerSmartContract: `contract call`
  - UpdateSettingContract: `contract update`
  - UpdateEnergyLimitContract: `contract update`
  - ClearABIContract: `contract clear_abi`
- Witness
  - VoteWitnessContract: `system vote_witness`
  - WitnessCreateContract: `system create_witness`
  - WitnessUpdateContract: `system update_witness`
  - WithdrawBalanceContract: `system withdraw_reward` - withdraw SR rewards
  - UpdateBrokerageContract: `system update_brokerage`
- Proposal
  - ProposalCreateContract: `system create_proposal`
  - ProposalApproveContract: `system approve_proposal` `system disapprove_proposal`
  - ProposalDeleteContract: `system delete_proposal`
- Exchange
  - [ ] ExchangeCreateContract
  - [ ] ExchangeInjectContract
  - [ ] ExchangeWithdrawContract
  - [ ] ExchangeTransactionContract
- ShieldedTransfer
  - [ ] ShieldedTransferContract
- ~~Deprecated~~
  - Storage deprecated
    - BuyStorageContract
    - BuyStorageBytesContract
    - SellStorageContract
  - Deprecated account
    - SetAccountIdContract - id useless?
    - AccountCreateContract - transfering creates account
  - VoteAssetContract

### Chain Lookup

```text
get subcommand
    account               Retrieve an account from the blockchain
    account_permission    Retrieve account permision info from the blockchain
    account_resource      Retrieve energy and bandwidth usage of an account
    asset                 Get details of a TRC10 token
    block                 Retrieve a full block from the blockchain
    brokerage             Get brokerage info, voting sharing ratio
    contract              Get details of a smart contract
    node                  Get current connected node state information
    proposal              Get details of a proposal
    reward                Get reward info, the unwithdrawn voting reward
    transaction           Retrieve a transaction from the blockchain
    transaction_info      Retrieve receipt of atransaction

list subcommand
    asset        Retrieve list of all tokens
    exchange     Retrive list of all exchanges
    node         List the nodes which is connecting to the network
    parameter    List chain parameters
    proposal     Retrive list of all proposals
    witness      Query the list of Super Representatives
```

### Local Wallet Management

```console
> ./target/debug/wallet-cli wallet create --password YOUR_PASSWORD
Wallet created!
> ./target/debug/wallet-cli wallet open
Wallet opened!
> ./target/debug/wallet-cli wallet create_key  # create a random key
Address: TMd3p......4JstUBsxen
Public:  f19f2d5b2c4067a.......7f0d1faaa094a23704d9
Private: 884f5218eb5da..............6809aa8da19d406
> ./target/debug/wallet-cli wallet keys  # list all keys
......(omitted)......
> ./target/debug/wallet-cli wallet --help  # get help
```

### Common Transaction Options

```text
FLAGS:
    -d, --dont-broadcast    Don't broadcast transaction to the network (just print to stdout)
    -h, --help              Prints help information
    -s, --skip-sign         Skip actual sign process

OPTIONS:
    -k, --account <account>                The account address used for signing
    -x, --expiration <expiration>          Set the time in seconds before a transaction expires
        --fee-limit <fee-limit>            Maximum value of TRX allowed consumed
        --permission-id <permission-id>    Permission id used by transaction [possible values: 0, 2, 1]
    -K, --private-key <private-key>        The private key used for signing
    -r, --ref-block <ref-block>            Set the reference block num or block id used for TAPOS
```
