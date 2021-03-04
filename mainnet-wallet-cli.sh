#!/bin/bash


cargo build --release -p walletd &>/dev/null

cargo run --release -p wallet-cli -- $@
