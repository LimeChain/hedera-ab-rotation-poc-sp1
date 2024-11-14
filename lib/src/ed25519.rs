use derive_more::derive::Deref;
use serde_big_array::Array;
use smallvec::SmallVec;

use crate::address_book::MAXIMUM_VALIDATORS;

#[repr(transparent)]
#[derive(Debug, Deref)]
pub struct VerifyingKey(pub ed25519_dalek::VerifyingKey);

pub const PUBLIC_KEY_LENGTH: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;
pub const SIGNATURE_LENGTH: usize = ed25519_dalek::SIGNATURE_LENGTH;

impl VerifyingKey {
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LENGTH]) -> Result<Self, ()> {
        ed25519_dalek::VerifyingKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| ())
    }
}

///////////

#[repr(transparent)]
#[derive(Debug, Deref, PartialEq, Eq)]
pub struct Signature(pub ed25519_dalek::Signature);
#[repr(transparent)]
#[derive(Debug, Deref)]
pub struct Signatures(pub SmallVec<[Option<Signature>; MAXIMUM_VALIDATORS]>);

pub type SignatureIn = Array<u8, { SIGNATURE_LENGTH }>;
pub type SignaturesIn = SmallVec<[Option<SignatureIn>; MAXIMUM_VALIDATORS]>;

impl TryFrom<SignatureIn> for Signature {
    type Error = ();

    fn try_from(value: SignatureIn) -> Result<Self, Self::Error> {
        Ok(Self(<ed25519_dalek::Signature>::from_bytes(&value)))
    }
}

impl TryFrom<SignaturesIn> for Signatures {
    type Error = ();

    fn try_from(value: SignaturesIn) -> Result<Self, Self::Error> {
        value
            .into_iter()
            .map(|ms| match ms {
                Some(s) => TryFrom::try_from(s).map(Option::Some),
                None => Ok(None),
            })
            .collect::<Result<SmallVec<[_; MAXIMUM_VALIDATORS]>, _>>()
            .map_err(|_| ())
            .map(Self)
    }
}
