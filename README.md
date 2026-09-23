# Valv CLI & Yazi Plugin

Standalone CLI tool and Yazi plugin to encrypt, decrypt, and transparently
mount vaults compatible with [Valv
v2](https://github.com/Arctosoft/Valv-Android)
(Android vault application).

## Key Features

- **Transparent in-memory vault mounting**: Open a Valv vault folder as a
  regular directory. Enter password once; browse, open, and edit files
  transparently.
- **Real-time auto-encryption**: Any file added or edited inside the mounted
  directory is automatically encrypted back into the vault. Deletions in the
  mount are reflected in the vault.
- **Session lifecycle tied to Yazi**: The background sync daemon monitors
  Yazi's process ID. When Yazi closes, the session automatically performs a
  final sync, wipes the in-memory directory, and exits cleanly.
- **100% Unprivileged (No Admin/Sudo Needed)**: Both the CLI and Yazi plugin
  install into user directories (`~/.cargo/bin` and `~/.config/yazi/plugins/`).
  Mounting uses standard user-accessible RAM tmpfs (`/dev/shm`), requiring zero
  root permissions, kernel modules, or `sudo`.
- **Format compatibility**: Full compatibility with Valv file structure version
  2 (ChaCha20 stream cipher, PBKDF2-HMAC-SHA512 key derivation with 50,000
  iterations). Supports decrypting legacy version 1 files.
- **Direct CLI operations**: Fast standalone `encrypt`, `decrypt`, and
  `--stdout` streaming commands for scripting and single/batch file operations.

---

## Installation (User Space / No Admin Required)

No root or administrative privileges are needed for installation or operation.

### 1. Install the CLI tool

From the repository:

```sh
cargo install --path valv-cli
```

This compiles and installs the binary to `~/.cargo/bin/valv`. Ensure
`~/.cargo/bin` is in your `$PATH`.

Or, without cloning the repo explicitly:

```sh
cargo install --git https://github.com/gierdo/vault-cli.git
```

### 2. Install the Yazi plugin

Install the  plugin into your user Yazi config:

```sh
ya pkg add gierdo/valv-cli:valv
```

### 3. Add Keymap to Yazi

Add the following to `~/.config/yazi/keymap.toml`:

```toml
[[mgr.prepend_keymap]]
on   = [ "u", "v" ]
run  = "plugin valv"
desc = "Valv: Open/lock vault or encrypt/decrypt files"
```

### 4. Optional: Install GNOME Files (Nautilus) Integration

Symlink the GUI helper and Nautilus scripts:

```sh
mkdir -p ~/.local/bin ~/.local/share/nautilus/scripts
ln -sfn "$(pwd)/valv.nautilus/valv-gui" ~/.local/bin/valv-gui
ln -sfn "$(pwd)/valv.nautilus/scripts" ~/.local/share/nautilus/scripts/Valv
```

Right-click any folder or file in Nautilus -> **Scripts** -> **Valv** to
open/lock vaults or encrypt/decrypt files.

---

## Transparent Vault Workflow in Yazi

### Opening a Vault

1. In Yazi, navigate to or hover over a folder containing `.valv` files.
2. Press `u v`.
3. Enter your vault password in the obscured input prompt (asked only once).
4. Yazi immediately navigates (`cd`) into an in-memory transparent directory
   (`/dev/shm/valv-<uid>/<vault>-<pid>`).
5. All vault files are displayed with their original filenames and extensions.

### Interacting with Files

- **Preview & Open**: Preview images/text and open files with your default apps
  or editor (`nvim`, image viewers, video players).
- **Adding files**: Paste or drop any file into the directory. The daemon
  automatically encrypts it into the vault with a matching suffix (`-i.valv`,
  `-v.valv`, `-x.valv`, etc.).
- **Editing files**: Modifying and saving a file automatically re-encrypts the
  file in the vault.
- **Deleting files**: Removing a file in the directory removes the
  corresponding encrypted file from the vault.

### Closing the Vault

- **Automatic**: Simply close Yazi. The background daemon detects Yazi's
  termination, completes any remaining encryption passes, wipes the decrypted
  directory in RAM, and exits.
- **Manual**: While inside the mounted directory, press `u v` again to lock the
  vault. Yazi navigates back to the vault folder and the session is cleared.

---

## CLI Usage

### Transparent Mount Commands

```sh
# Mount a vault directory transparently (runs background sync daemon)
valv mount ~/Pictures/Vault

# Mount with password from stdin (no password in shell history or ps)
echo "my_password" | valv mount ~/Pictures/Vault --stdin-password

# Mount and tie lifecycle to a specific PID (e.g. terminal or parent process)
valv mount ~/Pictures/Vault --watch-pid 12345

# Lock and unmount an active session
valv unmount /dev/shm/valv-1000/Vault-12345
# Or simply unmount the active session:
valv unmount
```

### Standalone Encryption & Decryption

```sh
# Decrypt a single .valv file
valv decrypt 32randomchars-i.valv

# Decrypt multiple files to a directory
valv decrypt *.valv -o ./restored/

# Stream decrypted content directly to stdout without saving to disk
valv decrypt --stdout movie-v.valv | mpv -

# Encrypt a file (creates [random32]-i.valv with metadata)
valv encrypt photo.jpg

# Encrypt files into an output folder
valv encrypt doc.pdf anim.gif -o ~/Pictures/Vault/
```

### Options Reference

| Option | Description |
| --- | --- |
| `-p, --password <PASS>` | Master password |
| `--stdin-password` | Read password from standard input |
| `-o, --output <PATH>` | Output destination file or directory |
| `--watch-pid <PID>` | Process ID to monitor for automatic cleanup upon exit |
| `--foreground` | Run mount watcher in foreground rather than as daemon |
| `-f, --force` | Overwrite existing files |
| `-i, --iterations <NUM>` | PBKDF2 iterations for encryption (default: 50000) |
| `--stdout` | Decrypt directly to stdout |
| `-h, --help` | Display help |
| `-V, --version` | Display version |

---

## Security & Architecture Details

1. **In-Memory Decryption**: Decrypted files are stored in `/dev/shm/`
   (RAM-backed tmpfs). Plaintext data is never written to swap or persistent
   disk during an active session.
2. **User Isolation**: Mount directories are created with `0700` permissions
   (readable/writable exclusively by your user UID).
3. **Automatic Cleanup**: If Yazi exits or the process is killed, the watcher
   daemon performs a final sync and runs `remove_dir_all` on the mountpoint.
4. **Password Verification**: Passwords are authenticated against the vault
   before any files are decrypted or mounted. Incorrect passwords return exit
   code `2` immediately.
