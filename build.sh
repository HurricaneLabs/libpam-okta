#!/bin/sh

set -x

export CARGO_HOME=/cache/cargo

cargo build --release --bin okta-select-factor
cargo build --release --lib
mv target/release/libpam_okta.so target/release/pam_okta.so
