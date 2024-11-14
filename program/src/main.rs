//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use ab_rotation_lib::{
    address_book::digest_address_book_in,
    calculate_signers_weight, calculate_total_weight,
    statement::{Statement, StatementIn},
    PublicValuesStruct,
};
use alloy_sol_types::SolValue;

pub fn main() {
    println!("cycle-tracker-start: parsing statement_in");
    let statement_in = sp1_zkvm::io::read::<StatementIn>();
    println!("cycle-tracker-end: parsing statement_in");

    assert!(
        statement_in.signatures.len() == statement_in.ab_curr.len(),
        "There has to be an (optional) signature for each current validator"
    );

    // Get the SHA256 of the current AB (using the provided ECALL)
    let ab_curr_hash: [u8; 32] = digest_address_book_in(&statement_in.ab_curr);

    let ab_next_hash: [u8; 32] = statement_in.ab_next_hash;

    // ... (attempt to) convert it to our internal representation
    println!("cycle-tracker-start: converting to statement");
    let statement: Statement = statement_in.try_into().unwrap();
    println!("cycle-tracker-end: converting to statement");

    println!("cycle-tracker-start: calculating total weight");
    let total_weight = calculate_total_weight(&statement);
    println!("cycle-tracker-end: calculating total weight");
    println!("cycle-tracker-start: calculating signers weight");
    let signers_weight = calculate_signers_weight(&statement);
    println!("cycle-tracker-end: calculating signers weight");

    // Assert that enough (30%) of the current validators have signed the next AB
    // NOTE: not using floats to avoid rounding issues
    let enough_signatures = (10 * signers_weight) >= (3 * total_weight);
    assert!(enough_signatures);

    let public_values = PublicValuesStruct {
        ab_curr_hash: ab_curr_hash.into(),
        ab_next_hash: ab_next_hash.into(),
    };

    // sp1_zkvm::io::hint(&cycle_count);
    sp1_zkvm::io::commit_slice(&public_values.abi_encode());
}
