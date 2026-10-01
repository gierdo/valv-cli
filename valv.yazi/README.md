# valv.yazi

Yazi plugin to transparently mount, create, encrypt, and decrypt [Age](https://github.com/FiloSottile/age) and [Valv](https://github.com/Arctosoft/Valv-Android) vaults.

## Features

- **Transparent directory mounting**: Open Age or Valv vault directories and browse all decrypted files with their original names and formats.
- **Automatic identity mounting**: Mounts Age vaults seamlessly using SOPS or configured Age identities without prompting for a password when available.
- **Interactive vault creation**: Initialize new Age vaults (with encrypted manifests) or Valv v2 vaults directly from Yazi.
- **Automatic encryption**: New files dropped into the mounted folder are automatically encrypted into the vault. Edits and deletions are synchronized in real time.
- **Tied to Yazi's session**: The background sync daemon automatically flushes changes, wipes the in-memory mount folder, and exits when Yazi closes.
- **No root required**: 100% user-space, using standard user RAM tmpfs (`/dev/shm`).

## Prerequisites

- `valv` CLI installed in `$PATH` (e.g. `cargo install --git https://github.com/gierdo/vault-cli.git`).

## Installation

```sh
ya pkg add gierdo/valv-cli:valv
```

Add this to `~/.config/yazi/keymap.toml`:

```toml
[[mgr.prepend_keymap]]
on   = [ "u", "v" ]
run  = "plugin valv"
desc = "Valv: Open/lock vault, create vault, or encrypt/decrypt files"
```

## Usage

1. **Open a vault**: Hover over or enter a vault folder and press `u v`. If an Age identity is configured, it unlocks automatically; otherwise, enter your password/passphrase once.
2. **Create a vault**: Press `u v` in an unencrypted folder to initialize a new Age vault or Valv v2 vault.
3. **Browse & edit**: Yazi navigates into the in-memory transparent directory. Open, edit, preview, and add files as usual.
4. **Lock / exit**:
   - Simply quit Yazi: the background watcher syncs pending changes, cleans up the decrypted directory in RAM, and exits.
   - Or press `u v` again while inside the mounted directory to manually lock and return to your vault folder.
