# Valv CLI & Yazi Plugin

Standalone CLI tool and Yazi plugin to encrypt, decrypt, and transparently
mount vaults in both [Age](https://github.com/FiloSottile/age) format and
[Valv v2](https://github.com/Arctosoft/Valv-Android) (Android vault application)
format.

## Key Features

- **Transparent in-memory vault mounting**: Open an Age or Valv vault directory
  as a regular filesystem directory in RAM (`/dev/shm`). Unlock once via Age
  identity or password; browse, preview, and edit files transparently.
- **Dual format support**: Full support for both modern Age encryption
  (X25519, SSH keys, Age passphrases) and Valv v2 format (ChaCha20 stream cipher,
  PBKDF2-HMAC-SHA512 with 50,000 iterations).
- **Encrypted Age Vault Manifests**: Vaults can contain an encrypted manifest
  (`.age_vault.toml.age` or `.age_vault.toml.valv`) storing recipient keys. When
  mounted, the manifest is presented as `.age_vault.toml`. Editing recipients in
  the manifest live re-encrypts the vault files on the fly.
- **Automatic identity and SOPS integration**: Discovers Age identities from
  standard SOPS paths (`$SOPS_AGE_KEY_FILE`, `~/.config/sops/age/keys.txt`, etc.)
  or user config, unlocking vaults without repeated password prompts.
- **Real-time auto-encryption**: Any file added or edited inside the mounted
  directory is automatically encrypted back into the vault. Deletions in the
  mount are synchronized to the vault.
- **Session lifecycle tied to process or Yazi**: The background sync daemon
  monitors the parent process or specified PID (such as Yazi). When the process
  closes, the session completes a final sync, wipes the in-memory directory, and
  exits cleanly.
- **100% Unprivileged (No Admin/Sudo Needed)**: Both the CLI and plugins install
  into user directories. Mounting uses standard user-accessible RAM tmpfs
  (`/dev/shm`), requiring zero root permissions, kernel modules, or `sudo`.
- **Thumbnail generation & cache prevention**: Automatically creates `-t.valv` or
  `-t.age` thumbnail companions for image/video files, and prevents desktop
  thumbnailers from leaking unencrypted cached thumbnails into `~/.cache/thumbnails`.
- **Direct CLI operations**: Fast standalone `init`, `mount`, `unmount`, `mounts`,
  `encrypt`, `decrypt`, and `--stdout` streaming commands for scripting and batch
  file operations.

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

Or, install directly from git:

```sh
cargo install --git https://github.com/gierdo/valv-cli.git
```

### 2. Install the Yazi plugin

Install the plugin into your user Yazi config:

```sh
ya pkg add gierdo/valv-cli:valv
```

### 3. Add Keymap to Yazi

Add the following to `~/.config/yazi/keymap.toml`:

```toml
[[mgr.prepend_keymap]]
on   = [ "u", "v" ]
run  = "plugin valv"
desc = "Valv: Open/lock vault, create vault, or encrypt/decrypt files"
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

## Configuration File

Valv searches for a configuration file in the following order:

1. Path specified by `-c, --config <PATH>`
2. Path specified by the `VALV_CONFIG` environment variable
3. `$XDG_CONFIG_HOME/valv/config.toml` (or `~/.config/valv/config.toml`)

### Example `~/.config/valv/config.toml`

```toml
[age]
# Default identity file (or SSH private key) used for decryption
identity = "~/.config/age/key.txt"

# Additional identity files
identities = [
    "~/.ssh/id_ed25519",
    "/etc/backup/age_key.txt"
]

# Single default recipient public key
recipient = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"

# Multiple default recipient public keys
recipients = [
    "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleRecipientKey"
]

# Recipient files containing lists of recipient public keys
recipients_file = "~/.config/age/recipients.txt"
recipients_files = [
    "~/.config/age/team_keys.txt"
]
```

If no identity files are configured, Valv automatically searches standard SOPS
paths for default Age keys:
- `$SOPS_AGE_KEY_FILE`
- `$XDG_CONFIG_HOME/sops/age/keys.txt`
- `~/.config/sops/age/keys.txt`
- `~/Library/Application Support/sops/age/keys.txt` (macOS)
- `%APPDATA%/sops/age/keys.txt` (Windows)

---

## Age Vault Functionality

Valv provides native Age vault support with identity discovery and encrypted
in-vault manifests.

### 1. Encrypted Manifest (`.age_vault.toml.age`)

When an Age vault is initialized with `valv init`, an encrypted manifest is
stored in the vault root (named `.age_vault.toml.age` or `age_vault.toml.age`).
The manifest holds the recipient keys and identity mappings for that vault:

```toml
recipient = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
recipients = [
    "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleRecipientKey"
]
recipients_file = "~/.config/age/recipients.txt"
```

The manifest itself is encrypted with the vault's recipient keys or passphrase.
When mounting, the manifest is automatically decrypted into `.age_vault.toml`
inside the in-memory mount folder.

### 2. Live Recipient Updates & Re-Encryption

While a vault is mounted:
- You can edit `.age_vault.toml` directly inside the mounted directory to add or
  remove recipient keys, identity files, or recipient lists.
- The sync daemon detects manifest edits in real time and automatically
  re-encrypts the vault files and the manifest with the updated recipients.
- No manual unmount or re-encryption step is required.

### 3. Recipient Key Extraction

Valv extracts recipient public keys from:
- Explicit recipient keys (`age1...`, `ssh-ed25519 ...`, `ssh-rsa ...`, `ecdsa-sha2-...`)
- Age secret keys (`AGE-SECRET-KEY-1...`, converted to their corresponding public key)
- Identity files containing `# public key:` or `# recipient:` header comments
- Companion public keys for SSH identity files (e.g. `id_ed25519.pub`)
- Recipients files passed via `-R, --recipients-file` or configured in the manifest

### 4. File Suffixes

Files in an Age vault use format suffixes indicating their category:
- Image files: `[random16]-i.age`
- Animated GIFs: `[random16]-g.age`
- Videos: `[random16]-v.age`
- Other documents/archives: `[random16]-x.age`
- Thumbnails: `[random16]-t.age`

For Valv v2 vaults, `.valv` suffixes (`-i.valv`, `-g.valv`, `-v.valv`, `-x.valv`,
`-t.valv`) are used instead.

---

## Transparent Vault Workflow in Yazi

### Opening a Vault

1. In Yazi, navigate to or hover over a folder containing vault files (`.age` or `.valv`).
2. Press `u v`.
3. If an Age identity is found in SOPS, config, or identity files, the vault
   mounts automatically without prompting. Otherwise, enter your vault
   password in the obscured input prompt.
4. Yazi immediately navigates (`cd`) into an in-memory transparent directory
   (`/dev/shm/valv-<uid>/<vault>-<pid>`).
5. All vault files are displayed with their original filenames and directory structure.

### Interacting with Files

- **Preview & Open**: Preview images/text and open files with your default apps
  or editor (`nvim`, image viewers, video players).
- **Adding files**: Paste or drop any file or folder into the directory. The daemon
  automatically encrypts it into the vault with the matching suffix.
- **Editing files**: Modifying and saving a file automatically re-encrypts the
  file in the vault.
- **Deleting files**: Removing a file in the directory removes the
  corresponding encrypted file and companion thumbnail from the vault.

### Closing the Vault

- **Automatic**: Simply close Yazi. The background daemon detects Yazi's
  termination, completes any remaining encryption passes, wipes the decrypted
  directory in RAM, and exits.
- **Manual**: While inside the mounted directory, press `u v` again to lock the
  vault. Yazi navigates back to the vault folder and the session is cleared.

---

## CLI Usage

### 1. Vault Initialization (`init` / `create` / `new`)

```sh
# Initialize a new Age vault with a recipient public key
valv init ~/Pictures/Vault -r age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p

# Initialize with recipients from a recipients file
valv init ~/Pictures/Vault -R ~/.config/age/recipients.txt

# Initialize in the current directory using configured Age / SOPS identities
valv init

# Initialize a Valv v2 format vault with password
valv init ~/Pictures/Vault --valv

# Overwrite existing manifest
valv init ~/Pictures/Vault -r age1... -f
```

### 2. Transparent Mount Commands (`mount` / `open`)

```sh
# Mount a vault directory transparently (runs background sync daemon)
valv mount ~/Pictures/Vault

# Mount current directory
valv mount

# Mount using an explicit Age identity file
valv mount ~/Pictures/Vault -k ~/.config/age/my_key.txt

# Mount with password from stdin
echo "my_password" | valv mount ~/Pictures/Vault --stdin-password

# Mount and tie lifecycle to a specific PID (e.g. terminal or parent process)
valv mount ~/Pictures/Vault --watch-pid 12345

# Mount without tying lifecycle to any PID
valv mount ~/Pictures/Vault --no-watch

# Mount explicitly using FUSE driver (on-demand streaming decryption)
valv mount ~/Pictures/Vault --driver fuse

# Mount explicitly using tmpfs driver (in-memory RAM sync)
valv mount ~/Pictures/Vault --driver tmpfs

# Mount to a custom destination directory
valv mount ~/Pictures/Vault -o /tmp/custom_mount
```

### 3. Unmount Commands (`unmount` / `close`)

```sh
# Unmount by mount path
valv unmount /dev/shm/valv-1000/Vault-12345

# Unmount by vault source directory
valv unmount ~/Pictures/Vault

# Unmount current directory / active mount
valv unmount
```

### 4. List Active Mounts (`mounts` / `list` / `ls`)

```sh
valv mounts
# or
valv ls
```

Output format:
```
/dev/shm/valv-1000/Vault-12345 -> /home/user/Pictures/Vault (42 files, daemon PID: 12346, watch PID: 12345)
```

### 5. Standalone Encryption (`encrypt`)

```sh
# Encrypt a single file into Age format with a recipient
valv encrypt photo.jpg -r age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p

# Encrypt multiple files or an entire folder recursively into a vault directory
valv encrypt doc.pdf anim.gif -o ~/Pictures/Vault/
valv encrypt ~/Documents/PlainFolder/ -o ~/Pictures/Vault/

# Encrypt using Valv v2 format with password
valv encrypt photo.jpg --valv -p "secret"

# Encrypt using custom PBKDF2 iterations for Valv v2
valv encrypt photo.jpg --valv -i 100000
```

### 6. Standalone Decryption (`decrypt`)

```sh
# Decrypt a single file using Age identity
valv decrypt 32randomchars-i.age -k ~/.config/age/key.txt

# Decrypt a single file using password
valv decrypt 32randomchars-i.valv -p "secret"

# Decrypt an entire vault directory recursively
valv decrypt ~/Pictures/Vault/ -o ./restored/

# Stream decrypted content directly to standard output without writing to disk
valv decrypt --stdout movie-v.age -k ~/.config/age/key.txt | mpv -
```

### 7. Default Command Inference

When running `valv` without an explicit subcommand:
- `valv` (no arguments) -> mounts current directory (`valv mount .`)
- `valv <dir>` -> mounts directory if it contains vault files, or encrypts directory if plain
- `valv <file.valv|file.age...>` -> decrypts vault files
- `valv <plain_files...>` -> encrypts files

---

## Options Reference

All options below can be passed globally or with subcommands:

| Option | Value | Default | Description |
| --- | --- | --- | --- |
| `-p, --password` | `<PASS>` | None (prompt) | Master password or passphrase |
| `--stdin-password` | Flag | `false` | Read password/passphrase from standard input |
| `-r, --recipient` | `<RECIPIENT>` | None | Age recipient public key (`age1...`, `ssh-...`, etc.). Can be specified multiple times. |
| `-R, --recipients-file` | `<PATH>` | None | Path to file containing Age recipient public keys. Can be specified multiple times. |
| `-k, --identity` | `<PATH>` | SOPS / Config | Path to Age identity file or SSH private key to decrypt with. Can be specified multiple times. |
| `--driver` | `<auto\|fuse\|tmpfs>` | `auto` | Mounting driver to use (`fuse` for on-demand FUSE mount, `tmpfs` for in-memory RAM sync, or `auto`) |
| `--fuse` | Flag | `false` | Force use of FUSE virtual filesystem driver |
| `--tmpfs` | Flag | `false` | Force use of tmpfs RAM sync driver |
| `--age` | Flag | Auto | Force use of Age format for encryption |
| `--valv` | Flag | Auto | Force use of Valv v2 format for encryption |
| `-o, --output` | `<PATH>` | Auto / `/dev/shm` | Destination file or directory for encryption, decryption, or mount point |
| `--watch-pid` | `<PID>` | Parent PID (Unix) | Process ID to monitor; session automatically cleans up and exits when PID terminates |
| `--no-watch` | Flag | `false` | Disable automatic PID watching during mount |
| `--foreground` | Flag | `false` | Run mount synchronization in foreground rather than as a background daemon |
| `-f, --force` | Flag | `false` | Overwrite existing destination files or existing vault manifests |
| `-i, --iterations` | `<NUM>` | `50000` | PBKDF2 iterations for Valv v2 password key derivation |
| `--stdout` | Flag | `false` | Stream decrypted content directly to standard output |
| `-c, --config` | `<PATH>` | Config path | Path to configuration TOML file |
| `-h, --help` | Flag | | Display help message |
| `-V, --version` | Flag | | Display version |

---

## Security & Architecture Details

1. **In-Memory Decryption**: Decrypted files are stored in `/dev/shm/`
   (RAM-backed tmpfs). Plaintext data is never written to swap or persistent
   disk during an active session.
2. **User Isolation & File Permissions**: Mount directories are created with
   `0700` permissions (readable/writable exclusively by your user UID). Decrypted
   files are created with `0600` permissions on Unix.
3. **Desktop Cache Mitigation**: Mount directories include `.nomedia` and a
   symlink from `.thumbnails` to `/dev/null` to prevent desktop thumbnailers
   from caching unencrypted media into `~/.cache/thumbnails`.
4. **Memory Zeroization**: Passwords and secret key buffers are securely zeroized
   in memory after use.
5. **Automatic Cleanup & Data Preservation**: If the watched process terminates
   or the daemon receives a termination signal (`SIGINT`, `SIGTERM`, `SIGHUP`),
   the daemon completes any pending encryption passes, preserves unsynced
   subdirectories, wipes the mount directory in RAM, and exits cleanly.
6. **Authentication & Credential Verification**: Passwords and identities are
   authenticated against the vault header/manifest before mounting or batch
   decryption starts.
