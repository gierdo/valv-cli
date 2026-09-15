# Valv Nautilus Integration

Native integration for GNOME Files (Nautilus) using standard Nautilus Scripts
and Zenity password prompts.

## Features

- **Open / Unlock Vault**: Right-click any directory containing `.valv` files
  -> **Scripts** -> **Valv** -> **open_vault**. Enter your password in the GUI
  prompt; the decrypted vault is transparently mounted into RAM (`/dev/shm`)
  and immediately opened in a new Nautilus window.
- **Auto-Syncing**: Drag, drop, save, or edit files inside the mounted folder.
  Changes are automatically re-encrypted into the vault with thumbnails in the
  background.
- **Lock Vault**: Right-click anywhere inside the vault or on the mount folder
  -> **Scripts** -> **Valv** -> **lock_vault**. The vault session closes and
  RAM tmpfs is wiped.
- **Encrypt / Decrypt Files**: Select any files -> **Scripts** -> **Valv** ->
  **encrypt_with_valv** (or **decrypt_with_valv**).

## Prerequisites

- `valv` CLI installed (`~/.cargo/bin/valv`)
- `zenity` (standard on GNOME, installed via `sudo apt install zenity` if missing)
- `notify-send` (standard on GNOME for desktop notifications)

## Quick Installation

Run the following commands in the `valv-cli` repository root:

```sh
# 1. Symlink or copy valv-gui helper to user binary directory (~/.local/bin)
mkdir -p ~/.local/bin
ln -sfn "$(pwd)/valv.nautilus/valv-gui" ~/.local/bin/valv-gui

# 2. Symlink the scripts directory into Nautilus Scripts:
mkdir -p ~/.local/share/nautilus/scripts
ln -sfn "$(pwd)/valv.nautilus/scripts" ~/.local/share/nautilus/scripts/Valv
```

That's it! Nautilus detects scripts immediately without needing to restart.

## Usage

1. In Nautilus, navigate to a directory containing `.valv` files.
2. Right-click the folder (or right-click blank space while inside it) ->
   **Scripts** -> **Valv** -> **open_vault**.
3. Type the master password into the Zenity dialog.
4. A new Nautilus window appears displaying the decrypted files in `/dev/shm`.
5. When finished, right-click anywhere -> **Scripts** -> **Valv** -> **lock_vault**.
