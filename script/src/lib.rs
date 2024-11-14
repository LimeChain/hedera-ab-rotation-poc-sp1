use ab_rotation_lib::{address_book::AddressBookIn, statement::StatementIn};
use serde_big_array::Array;
use smallvec::SmallVec;

pub fn generate_statement<const VALIDATORS_COUNT: usize>() -> ([u8; 32], [u8; 32], StatementIn) {
    let validators = ab_rotation_lib::signers::gen_validators::<VALIDATORS_COUNT>();

    let ab_next: AddressBookIn = Default::default();
    let ab_next_hash = ab_rotation_lib::address_book::digest_address_book_in(&ab_next);

    let ab_curr: AddressBookIn = SmallVec::from_vec(
        validators
            .verifying_keys_with_weights([1; VALIDATORS_COUNT])
            .map(|(a, b)| (Array(a), b))
            .to_vec(),
    );
    let ab_curr_hash = ab_rotation_lib::address_book::digest_address_book_in(&ab_curr);

    let message = ab_next_hash;

    // NOTE: a third of the validators, rounded up
    let signatures_count = (VALIDATORS_COUNT + 2) / 3;
    let signatures = validators
        .all_sign(signatures_count, &message)
        .to_vec()
        .into();

    let statement = StatementIn {
        ab_curr,
        ab_next_hash,
        signatures,
    };

    (ab_curr_hash, ab_next_hash, statement)
}
