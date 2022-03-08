extern crate chacha20poly1305;

use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, NewAead};

use crate::argon2id;

use js_sys::{Uint8Array};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn chacha20_encrypt(key: &[u8], msg: &[u8]) -> Option<Uint8Array> {
  let h = argon2id::hash(key);

  let k = Key::from_slice(h.as_slice());
  let cipher = ChaCha20Poly1305::new(k);
  let nonce = Nonce::from_slice(b"unique nonce");
  if k.is_empty() {
    return None;
  }

  cipher.encrypt(nonce, msg)
  .map(|v| Uint8Array::from(v.as_slice()))
  .ok()
}

#[wasm_bindgen]
pub fn chacha20_decrypt(key: &[u8], msg: &[u8]) -> Option<Uint8Array> {
  let h = argon2id::hash(key);

  let k = Key::from_slice(h.as_slice());
  let cipher = ChaCha20Poly1305::new(k);
  let nonce = Nonce::from_slice(b"unique nonce");
  if k.is_empty() {
    return None;
  }

  cipher.encrypt(nonce, msg)
  .map(|v| Uint8Array::from(v.as_slice()))
  .ok()
}