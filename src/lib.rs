#![allow(dead_code)]
// vault.rs — vault format, crypto, load/save. No CLI dependencies.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Algorithm, Argon2, Params, Version,
};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

pub const MAGIC: &[u8; 8] = b"PWMGRv01";
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const HEADER_LEN: usize = 8 + SALT_LEN + 4 + 4 + 4 + NONCE_LEN; // 48

pub const ARGON2_M_COST: u32 = 19 * 1024;
pub const ARGON2_T_COST: u32 = 2;
pub const ARGON2_P_COST: u32 = 1;

#[derive(thiserror::Error, Debug)]
pub enum VaultError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("not a pass-manager vault (magic: {0})")]
    BadMagic(String),

    #[error("vault file too short ({0} bytes, need at least {1})")]
    TooShort(usize, usize),

    #[error("bad argon2 params: {0}")]
    BadParams(String),

    #[error("argon2: {0}")]
    Kdf(String),

    #[error("encryption failed")]
    Encrypt,

    #[error("decryption failed (wrong password or corrupted vault)")]
    Decrypt,

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("no entry for '{0}'")]
    NoEntry(String),
}

impl VaultError {
    pub fn exit_code(&self) -> i32 {
        match self {
            VaultError::Decrypt | VaultError::NoEntry(_) => 1,
            VaultError::Io(_)
            | VaultError::BadMagic(_)
            | VaultError::TooShort(_, _)
            | VaultError::Json(_) => 2,
            VaultError::BadParams(_) | VaultError::Kdf(_) | VaultError::Encrypt => 3,
        }
    }

    /// What to show on an unlock screen. A `Decrypt` error means
    /// "wrong password or corrupt file" — everything else is a real problem.
    pub fn is_wrong_password(&self) -> bool {
        matches!(self, VaultError::Decrypt)
    }
}

pub type Result<T> = std::result::Result<T, VaultError>;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Entry {
    pub site: String,
    pub user: String,
    pub password: String,
    pub notes: String,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Vault {
    pub entries: Vec<Entry>,
}

impl Vault {
    pub fn find(&self, site: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.site == site)
    }

    pub fn find_mut(&mut self, site: &str) -> Option<&mut Entry> {
        self.entries.iter_mut().find(|e| e.site == site)
    }

    pub fn add(&mut self, entry: Entry) -> Result<()> {
        if self.find(&entry.site).is_some() {
            return Err(VaultError::NoEntry(format!(
                "{} (already exists)", entry.site
            )));
        }
        self.entries.push(entry);
        Ok(())
    }

    pub fn remove(&mut self, site: &str) -> Result<()> {
        let before = self.entries.len();
        self.entries.retain(|e| e.site != site);
        if self.entries.len() == before {
            return Err(VaultError::NoEntry(site.into()));
        }
        Ok(())
    }
}

pub fn derive_key(
    password: &str,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|e| VaultError::BadParams(e.to_string()))?;
    let instance = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let salt_b64 = STANDARD_NO_PAD.encode(salt);
    let salt_string =
        SaltString::from_b64(&salt_b64).map_err(|e| VaultError::Kdf(e.to_string()))?;

    let hash = instance
        .hash_password(password.as_bytes(), &salt_string)
        .map_err(|e| VaultError::Kdf(e.to_string()))?;

    let binding = hash.hash.unwrap();
    let hash_bytes = binding.as_bytes();
    let key_slice: &[u8; 32] = hash_bytes[..32]
        .try_into()
        .map_err(|e: std::array::TryFromSliceError| VaultError::Kdf(e.to_string()))?;
    Ok(Zeroizing::new(*key_slice))
}

pub fn encrypt_payload(vault: &Vault, key: &[u8; 32]) -> Result<(Vec<u8>, [u8; NONCE_LEN])> {
    let mut plaintext = serde_json::to_vec(vault)?;

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| VaultError::Encrypt)?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|_| VaultError::Encrypt)?;

    plaintext.zeroize();
    Ok((ciphertext, nonce_bytes))
}

pub fn decrypt_payload(ciphertext: &[u8], nonce_bytes: &[u8], key: &[u8; 32]) -> Result<Vault> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| VaultError::Decrypt)?;
    let nonce = Nonce::from_slice(nonce_bytes);

    let mut plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| VaultError::Decrypt)?;

    let vault = serde_json::from_slice(&plaintext)?;
    plaintext.zeroize();
    Ok(vault)
}

pub fn check_vault_header(path: &str) -> Result<()> {
    let blob = fs::read(path)?;
    if blob.len() < HEADER_LEN {
        return Err(VaultError::TooShort(blob.len(), HEADER_LEN));
    }
    if &blob[..8] != MAGIC {
        let magic = String::from_utf8_lossy(&blob[..8]).into_owned();
        return Err(VaultError::BadMagic(magic));
    }
    Ok(())
}

pub fn load_vault(path: &str, password: &str) -> Result<Vault> {
    check_vault_header(path)?;
    let blob = fs::read(path)?;

    let salt = &blob[8..24];
    let m_cost = u32::from_le_bytes(blob[24..28].try_into().unwrap());
    let t_cost = u32::from_le_bytes(blob[28..32].try_into().unwrap());
    let p_cost = u32::from_le_bytes(blob[32..36].try_into().unwrap());
    let nonce = &blob[36..48];
    let payload = &blob[48..];

    let key = derive_key(password, salt, m_cost, t_cost, p_cost)?;
    decrypt_payload(payload, nonce, &key)
}

pub fn save_vault(path: &str, vault: &Vault, password: &str) -> Result<()> {
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);

    let key = derive_key(password, &salt, ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST)?;
    let (ciphertext, nonce) = encrypt_payload(vault, &key)?;

    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&ARGON2_M_COST.to_le_bytes());
    out.extend_from_slice(&ARGON2_T_COST.to_le_bytes());
    out.extend_from_slice(&ARGON2_P_COST.to_le_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);

    let tmp = format!("{}.tmp", path);
    fs::write(&tmp, &out)?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;

    if Path::new(path).exists() {
        let _ = fs::copy(path, format!("{}.bak", path));
    }

    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PW: &str = "test-master-password";
    const TEST_M_COST: u32 = 8 * 1024;
    const TEST_T_COST: u32 = 1;
    const TEST_P_COST: u32 = 1;

    fn test_salt() -> [u8; SALT_LEN] {
        [7u8; SALT_LEN]
    }

    fn sample_vault() -> Vault {
        Vault {
            entries: vec![
                Entry {
                    site: "github".into(),
                    user: "alice".into(),
                    password: "p@ss".into(),
                    notes: "2FA on".into(),
                },
                Entry {
                    site: "email".into(),
                    user: "bob".into(),
                    password: "hunter2".into(),
                    notes: String::new(),
                },
            ],
        }
    }

    #[test]
    fn derive_key_is_deterministic() {
        let salt = test_salt();
        let k1 = derive_key(PW, &salt, TEST_M_COST, TEST_T_COST, TEST_P_COST).unwrap();
        let k2 = derive_key(PW, &salt, TEST_M_COST, TEST_T_COST, TEST_P_COST).unwrap();
        assert_eq!(*k1, *k2);
    }

    #[test]
    fn different_password_gives_different_key() {
        let salt = test_salt();
        let k1 = derive_key(PW, &salt, TEST_M_COST, TEST_T_COST, TEST_P_COST).unwrap();
        let k2 = derive_key("other", &salt, TEST_M_COST, TEST_T_COST, TEST_P_COST).unwrap();
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn payload_round_trip() {
        let key = derive_key(PW, &test_salt(), TEST_M_COST, TEST_T_COST, TEST_P_COST).unwrap();
        let vault = sample_vault();

        let (ciphertext, nonce) = encrypt_payload(&vault, &key).unwrap();
        let recovered = decrypt_payload(&ciphertext, &nonce, &key).unwrap();

        assert_eq!(recovered.entries.len(), 2);
        assert_eq!(recovered.entries[0].site, "github");
        assert_eq!(recovered.entries[1].password, "hunter2");
    }

    #[test]
    fn wrong_password_decryption_fails() {
        let key_good = derive_key(PW, &test_salt(), TEST_M_COST, TEST_T_COST, TEST_P_COST).unwrap();
        let key_bad  = derive_key("wrong", &test_salt(), TEST_M_COST, TEST_T_COST, TEST_P_COST).unwrap();

        let (ciphertext, nonce) = encrypt_payload(&sample_vault(), &key_good).unwrap();
        let result = decrypt_payload(&ciphertext, &nonce, &key_bad);

        assert!(matches!(result, Err(VaultError::Decrypt)));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = derive_key(PW, &test_salt(), TEST_M_COST, TEST_T_COST, TEST_P_COST).unwrap();
        let (mut ciphertext, nonce) = encrypt_payload(&sample_vault(), &key).unwrap();

        let mid = ciphertext.len() / 2;
        ciphertext[mid] ^= 0x01;

        let result = decrypt_payload(&ciphertext, &nonce, &key);
        assert!(matches!(result, Err(VaultError::Decrypt)));
    }

    #[test]
    fn vault_add_remove() {
        let mut v = Vault::default();
        v.add(Entry {
            site: "a".into(), user: "u".into(),
            password: "p".into(), notes: String::new(),
        }).unwrap();
        assert!(v.find("a").is_some());

        // duplicate is rejected
        assert!(v.add(Entry {
            site: "a".into(), user: "u2".into(),
            password: "p2".into(), notes: String::new(),
        }).is_err());

        v.remove("a").unwrap();
        assert!(v.find("a").is_none());

        // removing a missing entry errors
        assert!(v.remove("a").is_err());
    }

    #[test]
    fn exit_codes_are_distinct() {
        assert_eq!(VaultError::Decrypt.exit_code(), 1);
        assert_eq!(VaultError::NoEntry("x".into()).exit_code(), 1);
        assert_eq!(VaultError::TooShort(0, 48).exit_code(), 2);
        assert_eq!(VaultError::Kdf("x".into()).exit_code(), 3);
    }
}
