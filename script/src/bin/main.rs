//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can be executed
//! or have a core proof generated.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release -- --execute
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release -- --prove
//! ```

use alloy_sol_types::SolType;
use clap::Parser;
use serde_big_array::Array;
use smallvec::SmallVec;
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};

use ab_rotation_lib::{address_book::AddressBookIn, statement::StatementIn, PublicValuesStruct};

use ab_rotation_script::generate_statement;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const AB_ROTATION_ELF: &[u8] = include_elf!("ab-rotation-program");

/// The number of validators that are created for the proving
// TODO: can be done with a runtime-known length
pub const VALIDATORS_COUNT: usize = 30;

/// The arguments for the command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    execute: bool,

    #[clap(long)]
    prove: bool,

    // #[clap(long, default_value_t = 1)]
    // validators_count: u32,
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Parse the command line arguments.
    let args = Args::parse();

    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }

    // Setup the prover client.
    let client = ProverClient::new();

    // Setup the inputs.
    let mut stdin = SP1Stdin::new();
    let (ab_curr_hash, ab_next_hash, statement) = generate_statement::<VALIDATORS_COUNT>();
    stdin.write(&statement);

    println!("validators_count: {}", VALIDATORS_COUNT);

    if args.execute {
        // Execute the program
        let (output, report) = client.execute(AB_ROTATION_ELF, stdin).run().unwrap();
        println!("Program executed successfully.");

        // Read the output.
        let decoded = PublicValuesStruct::abi_decode(output.as_slice(), true).unwrap();
        let PublicValuesStruct {
            ab_curr_hash: ab_curr_hash_decoded,
            ab_next_hash: ab_next_hash_decoded,
        } = decoded;
        println!("ab_curr_hash_decoded: {}", ab_curr_hash_decoded);
        println!("ab_next_hash_decoded: {}", ab_next_hash_decoded);

        assert_eq!(ab_curr_hash_decoded.0, ab_curr_hash);
        assert_eq!(ab_next_hash_decoded.0, ab_next_hash);
        println!("Values are correct!");

        // Record the number of cycles executed.
        println!("Number of cycles: {}", report.total_instruction_count());
    } else {
        // Setup the program for proving.
        let (pk, vk) = client.setup(AB_ROTATION_ELF);

        // Generate the proof
        let proof = client
            .prove(&pk, stdin)
            .run()
            .expect("failed to generate proof");

        println!("Successfully generated proof!");

        // Verify the proof.
        client.verify(&proof, &vk).expect("failed to verify proof");
        println!("Successfully verified proof!");
    }
}
