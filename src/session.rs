// Copyright 2016-2024 dbus-secret-service Contributors
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

// key exchange and crypto for session:
// 1. Before session negotiation (openSession), set private key and public key using DH method.
// 2. In session negotiation, send public key.
// 3. In session negotiation, exchange my public key for server's public key.
// 4. Use server public key and my private key to derive a shared AES key using HKDF.
// 5. Format Secret: aes iv is random seed, in secret struct it's the parameter (Array(Byte))
// 6. Format Secret: encode the secret value for the value field in secret struct.
//      This encoding uses the aes_key from the associated Session.

use std::fmt::Formatter;
use std::ops::{Mul, Rem, Shr};
use std::rc::Rc;
use std::time::Duration;

use dbus::arg::messageitem::MessageItem::{Str, Variant};
use dbus::blocking::BlockingSender;
use dbus::{arg::messageitem::MessageItem, blocking::SyncConnection, Message, Path};
use generic_array::{typenum::U16, GenericArray};
use hkdf::Hkdf;
use num::bigint::BigUint;
use num::integer::Integer;
use num::traits::{One, Zero};
use num::FromPrimitive;
use once_cell::sync::Lazy;
use rand::{rngs::OsRng, Rng};
use sha2::Sha256;

use crate::error::Error;
use crate::ss::{ALGORITHM_DH, ALGORITHM_PLAIN, SS_DBUS_NAME, SS_INTERFACE_SERVICE, SS_PATH};

// for key exchange
static DH_GENERATOR: Lazy<BigUint> = Lazy::new(|| BigUint::from_u64(0x2).unwrap());
static DH_PRIME: Lazy<BigUint> = Lazy::new(|| {
    BigUint::from_bytes_be(&[
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2,
        0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67,
        0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E,
        0x34, 0x04, 0xDD, 0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
        0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5,
        0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF,
        0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED, 0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE,
        0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ])
});

type AesKey = aes::cipher::generic_array::GenericArray<u8, U16>;

#[derive(Debug, Eq, PartialEq)]
pub enum EncryptionType {
    Plain,
    Dh,
}

#[derive(Clone)]
struct Keypair {
    private: BigUint,
    public: BigUint,
}

impl Keypair {
    fn generate() -> Self {
        let mut rng = OsRng {};
        let mut private_key_bytes = [0; 128];
        rng.fill(&mut private_key_bytes);

        let private_key = BigUint::from_bytes_be(&private_key_bytes);
        let public_key = pow_base_exp_mod(&DH_GENERATOR, &private_key, &DH_PRIME);

        Self {
            private: private_key,
            public: public_key,
        }
    }

    fn derive_shared(&self, server_public_key: &BigUint) -> AesKey {
        // Derive the shared secret the server and us.
        let common_secret = pow_base_exp_mod(server_public_key, &self.private, &DH_PRIME);

        let mut common_secret_bytes = common_secret.to_bytes_be();
        let mut common_secret_padded = vec![0; 128 - common_secret_bytes.len()];
        common_secret_padded.append(&mut common_secret_bytes);

        // hkdf

        // input keying material
        let ikm = common_secret_padded;
        let salt = None;

        // output keying material
        let mut okm = [0; 16];
        hkdf(ikm, salt, &mut okm);

        aes::cipher::generic_array::GenericArray::clone_from_slice(&okm)
    }
}

fn hkdf(ikm: Vec<u8>, salt: Option<&[u8]>, okm: &mut [u8]) {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let info = [];
    let (_, hk) = Hkdf::<Sha256>::extract(salt, &ikm);
    hk.expand(&info, okm)
        .expect("hkdf expand should never fail");
}

#[derive(Clone)]
pub struct Session<'a> {
    pub object_path: Path<'a>,
    keypair: Option<Keypair>,
    server_public_key: Option<BigUint>,
    shared_key: Option<AesKey>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("object_path", &self.object_path)
            .field(
                "secrets",
                if self.is_encrypted() {
                    "(Hidden)"
                } else {
                    "None"
                },
            )
            .finish()
    }
}

impl Session {
    pub fn new(bus: Rc<SyncConnection>, encryption: EncryptionType) -> Result<Self, Error> {
        match encryption {
            EncryptionType::Plain => {
                let m = Message::new_method_call(
                    SS_DBUS_NAME,
                    SS_PATH,
                    SS_INTERFACE_SERVICE,
                    "OpenSession",
                )
                .map_err(dbus::Error::new_failed)?
                .append2(
                    Str(ALGORITHM_PLAIN.to_owned()),
                    Variant(Box::new(Str("".to_owned()))),
                );

                // Call to session
                let r = bus.send_with_reply_and_block(m, Duration::from_millis(2000))?;
                let items = r.get_items();

                // Get session output
                let session_output_dbus = items.get(0).ok_or(Error::NoResult)?;
                let session_output_variant_dbus: &MessageItem =
                    session_output_dbus.inner().unwrap();

                // check session output is str
                session_output_variant_dbus.inner::<&str>().unwrap();

                // get session path
                let object_path_dbus = items.get(1).ok_or(Error::NoResult)?;
                let object_path: &Path = object_path_dbus.inner().unwrap();

                Ok(Session {
                    object_path: object_path.clone(),
                    keypair: None,
                    server_public_key: None,
                    shared_key: None,
                })
            }
            EncryptionType::Dh => {
                // crypto: create private and public key, send public key
                let keypair = Keypair::generate();

                // Negotiate encrypted session by providing our public key
                let message_bytes = keypair
                    .public
                    .to_bytes_be()
                    .iter()
                    .map(|&byte| MessageItem::from(byte))
                    .collect();
                let m = Message::new_method_call(
                    SS_DBUS_NAME,
                    SS_PATH,
                    SS_INTERFACE_SERVICE,
                    "OpenSession",
                )
                .map_err(dbus::Error::new_failed)?
                .append2(
                    Str(ALGORITHM_DH.to_owned()),
                    Variant(Box::new(MessageItem::new_array(message_bytes).unwrap())),
                );

                // Get session output and extract server public key from it
                let r = bus.send_with_reply_and_block(m, Duration::from_millis(2000))?;
                let items = r.get_items();
                let session_output = items.get(0).ok_or(Error::NoResult)?;
                let session_output_variant: &MessageItem = session_output.inner().unwrap();
                let session_output_vec: &Vec<_> =
                    session_output_variant.inner().map_err(|_| Error::Parse)?;
                let server_public_key_bytes = session_output_vec
                    .iter()
                    .map(|byte_dbus| byte_dbus.inner::<u8>().unwrap())
                    .collect();
                let server_public_key = BigUint::from_bytes_be(&server_public_key_bytes);

                // Derive shared AES key from server public key and our private key
                let shared_key = keypair.derive_shared(&server_public_key);

                // get session path to store
                let object_path_dbus = items.get(1).ok_or(Error::NoResult)?;
                let object_path: &Path = object_path_dbus.inner().unwrap();

                Ok(Session {
                    object_path: object_path.clone(),
                    keypair: Some(keypair),
                    server_public_key: Some(server_public_key),
                    shared_key: Some(shared_key),
                })
            }
        }
    }

    pub fn is_encrypted(&self) -> bool {
        !self.keypair.is_none()
    }

    pub fn get_shared_key(&self) -> AesKey {
        self.shared_key.clone().unwrap()
    }
}

/// from https://github.com/plietar/librespot/blob/master/core/src/util/mod.rs#L53
fn pow_base_exp_mod(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
    let mut base = base.clone();
    let mut exp = exp.clone();
    let mut result: BigUint = One::one();

    while !exp.is_zero() {
        if exp.is_odd() {
            result = result.mul(&base).rem(modulus);
        }
        exp = exp.shr(1);
        base = (&base).mul(&base).rem(modulus);
    }

    result
}

pub fn encrypt(data: &[u8], key: &AesKey, iv: &[u8]) -> Vec<u8> {
    use aes::cipher::block_padding::Pkcs7;
    use aes::cipher::{BlockEncryptMut, KeyIvInit};

    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
    let iv = GenericArray::from_slice(iv);
    Aes128CbcEnc::new(key, iv).encrypt_padded_vec_mut::<Pkcs7>(data)
}

pub fn decrypt(encrypted_data: &[u8], key: &AesKey, iv: &[u8]) -> Result<Vec<u8>, Error> {
    use aes::cipher::block_padding::Pkcs7;
    use aes::cipher::{BlockDecryptMut, KeyIvInit};

    type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
    let iv = GenericArray::from_slice(iv);
    Aes128CbcDec::new(key, iv)
        .decrypt_padded_vec_mut::<Pkcs7>(encrypted_data)
        .map_err(|_| Error::Crypto("message decryption failed"))
}

#[cfg(test)]
mod test {
    use std::rc::Rc;

    use dbus::{blocking::SyncConnection, channel::BusType};

    use super::*;

    #[test]
    fn should_create_plain_session() {
        let bus = SyncConnection::get_private(BusType::Session).unwrap();
        let session = Session::new(Rc::new(bus), EncryptionType::Plain).unwrap();
        assert!(!session.is_encrypted());
    }

    #[test]
    fn should_create_encrypted_session() {
        let bus = SyncConnection::get_private(BusType::Session).unwrap();
        let session = Session::new(Rc::new(bus), EncryptionType::Dh).unwrap();
        assert!(session.is_encrypted());
    }
}
