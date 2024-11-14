use derive_more::derive::Deref;
use serde_big_array::Array;
use smallvec::SmallVec;

use crate::ed25519::{self, Signature};

#[cfg(feature = "with_bls_aggregate")]
pub type BlsPublicKey = ();
pub type Weight = u64;

#[derive(Debug)]
pub struct AddressBookEntry {
    pub ed25519_public_key: ed25519::VerifyingKey,
    // #[cfg(feature = "with_bls_aggregate")]
    // pub bls_public_key: BlsPublicKey,
    pub weight: Weight,
}
#[repr(transparent)]
#[derive(Debug, Deref)]
pub struct AddressBook(pub SmallVec<[AddressBookEntry; MAXIMUM_VALIDATORS]>);

pub const MAXIMUM_VALIDATORS: usize = 64;

pub type AddressBookEntryIn = (Array<u8, { ed25519::PUBLIC_KEY_LENGTH }>, Weight);
pub type AddressBookIn = SmallVec<[AddressBookEntryIn; MAXIMUM_VALIDATORS]>;

impl TryFrom<AddressBookEntryIn> for AddressBookEntry {
    type Error = ();

    fn try_from(value: AddressBookEntryIn) -> Result<Self, Self::Error> {
        Ok(Self {
            ed25519_public_key: <ed25519::VerifyingKey>::from_bytes(&value.0)?,
            weight: value.1,
        })
    }
}

impl TryFrom<AddressBookIn> for AddressBook {
    type Error = ();

    fn try_from(value: AddressBookIn) -> Result<Self, Self::Error> {
        value
            .into_iter()
            .map(TryFrom::try_from)
            .collect::<Result<SmallVec<[_; MAXIMUM_VALIDATORS]>, _>>()
            .map_err(|_| ())
            .map(Self)
    }
}

pub fn digest_address_book_in(ab: &AddressBookIn) -> [u8; 32] {
    use sha2::{Sha256, Digest};

    // create a Sha256 object
    let mut hasher = Sha256::new();

    // NOTE: uses the same `bincode` as the `sp1_zkvm::io::read` and family
    let ab_bytes = bincode::serialize(ab).unwrap();

    // write input message
    hasher.update(&ab_bytes);

    // read hash digest and consume hasher
    let result: [u8; 32] = hasher.finalize().into();

    result
}

impl AddressBook {
    pub fn get_validator_weight_from_signature(
        &self,
        signature: &Signature,
        message: &[u8],
    ) -> Option<Weight> {
        self.iter().find_map(|abe| {
            abe.ed25519_public_key
                .verify_strict(message, signature)
                .ok()
                .map(|_| abe.weight)
        })
    }
}
