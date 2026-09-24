# vault-core

Shared library for the pass-manager family: vault format, crypto, and file I/O.

Used by:
- [`Pass-manager`](https://github.com/octavianmalopha13-tech/Pass-manager) — CLI
- [`Vault-tui`](https://github.com/octavianmalopha13-tech/Vault-tui) — TUI
- [`Vault-api`](https://github.com/octavianmalopha13-tech/vault-api) — HTTP API

## Format

# ---------- vault-core README ----------
cd ~/rust_learning/vault-core
cat > README.md <<'EOF'
# vault-core

Shared library for the pass-manager family: vault format, crypto, and file I/O.

Used by:
- [Pass-manager](https://github.com/octavianmalopha13-tech/Pass-manager) — CLI
- [Vault-tui](https://github.com/octavianmalopha13-tech/Vault-tui) — TUI
- [vault-api](https://github.com/octavianmalopha13-tech/vault-api) — HTTP API

## Format

    offset  size  field
    ------  ----  ---------------------------------------------
    0       8     magic "PWMGRv01"
    8       16    salt
    24      4     Argon2 m_cost (u32 LE, KiB)
    28      4     Argon2 t_cost (u32 LE)
    32      4     Argon2 p_cost (u32 LE)
    36      12    AES-GCM nonce
    48      ...   ciphertext + 16-byte tag

Argon2 parameters live in the file, so bumping the KDF cost doesn't
invalidate existing vaults.

## Guarantees

- Atomic writes: saves go to a `.tmp` sibling then rename(2) into place.
- Backups: the previous vault is copied to `vault.enc.bak` before each save.
- 0600 permissions enforced with chmod, not left to the umask.
- Zeroized secrets: master password, derived key, and decrypted JSON are
  wiped on drop.

## License

MIT
