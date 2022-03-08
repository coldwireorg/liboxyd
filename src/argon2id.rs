extern crate argon2;

use argon2::{hash_raw, Config};
use rand::{rngs::OsRng, RngCore};

pub fn hash(password: &[u8]) -> Vec<u8> {
  let mut salt = [0u8; 32];
  OsRng.fill_bytes(&mut salt);

  hash_raw(password, &salt, &Config::default()).unwrap()
} 