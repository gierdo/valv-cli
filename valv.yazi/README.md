# valv.yazi

Yazi plugin to transparently mount, encrypt, and decrypt [Valv](https://github.com/Arctosoft/Valv-Android) vaults.

## Features

- **Transparent directory mounting**: Open a vault directory and browse all decrypted files with their original names and formats.
- **Single password prompt**: Asks for password once with an obscured prompt upon opening the vault.
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
desc = "Valv: Open/lock vault or encrypt/decrypt files"
```

## Usage

1. **Open a vault**: Hover over or enter a folder containing `.valv` files and press `u v`. Enter your password once.
2. **Browse & edit**: Yazi navigates into the in-memory transparent directory. Open, edit, preview, and add files as usual.
3. **Lock / exit**:
   - Simply quit Yazi: the background watcher syncs pending changes, cleans up the decrypted directory in RAM, and exits.
   - Or press `u v` again while inside the mounted directory to manually lock and return to your vault folder.
