use ecies_ed25519::{
  decrypt, encrypt, generate_keypair, PublicKey,
  SecretKey,
};
use js_sys::{Array, Uint8Array};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn ecies_generate_keypair() -> Array {
  let mut rng = rand::thread_rng();

  let (sk, pk) = generate_keypair(&mut rng);
  let (sk, pk) = (sk.to_bytes(), pk.to_bytes());
  let (sk, pk) = (Uint8Array::from(&sk[..]), Uint8Array::from(&pk[..]));

  let ret = Array::new();
  ret.push(&sk);
  ret.push(&pk);
  ret
}

#[wasm_bindgen]
pub fn ecies_encrypt(receiver_pub: &[u8], msg: &[u8]) -> Option<Uint8Array> {
  let pk = PublicKey::from_bytes(receiver_pub).ok();
  if pk.is_none() {
      return None;
  }
  let mut rng = rand::thread_rng();
  encrypt(&pk.unwrap(), msg, &mut rng)
      .map(|v| Uint8Array::from(v.as_slice()))
      .ok()
}

#[wasm_bindgen]
pub fn ecies_decrypt(receiver_sec: &[u8], msg: &[u8]) -> Option<Uint8Array> {
  let sk = SecretKey::from_bytes(receiver_sec).ok();
  if sk.is_none() {
      return None;
  }
  decrypt(&sk.unwrap(), msg)
      .map(|v| Uint8Array::from(v.as_slice()))
      .ok()
}