// TODO: better error types
#![allow(clippy::result_unit_err)]

use alloy_sol_types::sol;

pub mod address_book;
pub mod ed25519;
pub mod signers;
pub mod statement;

use statement::Statement;

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct PublicValuesStruct {
        bytes32 ab_curr_hash;
        bytes32 ab_next_hash;
    }
}

pub fn calculate_total_weight(statement: &Statement) -> u64 {
    statement.ab_curr.iter().map(|abe| abe.weight).sum()
}

pub fn calculate_signers_weight(statement: &Statement) -> u64 {
    core::iter::zip(statement.ab_curr.0.iter(), statement.signatures.0.iter()).fold(
        0,
        |acc, (abe, ms)| -> u64 {
            let added_weight = ms
                .as_ref()
                .map(|signature| {
                    abe.ed25519_public_key
                        .verify_strict(&statement.ab_next_hash, signature)
                        .map(|_| abe.weight)
                        .expect("Invalid signature")
                })
                .unwrap_or(0);

            acc + added_weight
        },
    )
}
