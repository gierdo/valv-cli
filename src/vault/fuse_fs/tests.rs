use age::secrecy::ExposeSecret;
use rand::RngExt;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Cursor};
use std::time::Duration;

use fuser::MountOption;

use super::super::driver::ValvFuseFs;
use super::super::lifecycle::{has_fuse_support, unmount_fuse_target};
use crate::crypto::{
    decrypt_header_with_credentials, encrypt_stream, encrypt_stream_unified, Credentials,
    EncryptionMethod, VaultFormat,
};
use crate::vault::paths::collect_vault_files;

#[test]
fn test_has_fuse_support() {
    let _ = has_fuse_support();
}

#[test]
fn test_fuse_mount_read_write_lifecycle() {
    if !has_fuse_support() {
        return;
    }

    let temp_dir = std::env::temp_dir().join(format!(
        "valv_fuse_test_{}",
        rand::rng().random::<u32>()
    ));
    let vault_dir = temp_dir.join("vault");
    let mount_dir = temp_dir.join("mount");
    fs::create_dir_all(&vault_dir).unwrap();
    fs::create_dir_all(&mount_dir).unwrap();

    let password = b"TestFusePass123";
    let file_path = vault_dir.join("hello-x.valv");
    let mut out = BufWriter::new(File::create(&file_path).unwrap());
    encrypt_stream(
        &mut Cursor::new(b"Hello from FUSE"),
        &mut out,
        password,
        "hello.txt",
        1000,
    )
    .unwrap();
    drop(out);

    let fs = ValvFuseFs::new(
        &vault_dir,
        Some(password.to_vec()),
        VaultFormat::Valv,
        1000,
        vec![],
        vec![],
        vec![],
        None,
    )
    .expect("ValvFuseFs creation");

    let options = vec![MountOption::FSName("valv_test".to_string())];

    let session = match fuser::spawn_mount2(fs, &mount_dir, &options) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "Skipping test: spawn_mount2 failed (maybe no /dev/fuse permissions): {}",
                e
            );
            let _ = fs::remove_dir_all(&temp_dir);
            return;
        }
    };

    // 1. Read existing file
    let mut read_success = false;
    for _ in 0..50 {
        if let Ok(content) = fs::read_to_string(mount_dir.join("hello.txt")) {
            assert_eq!(content, "Hello from FUSE");
            read_success = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(read_success, "Should read hello.txt via FUSE");

    // 2. Read virtual .valv_session.json
    assert!(mount_dir.join(".valv_session.json").exists());
    let session_text = fs::read_to_string(mount_dir.join(".valv_session.json")).unwrap();
    assert!(session_text.contains("vault_dir"));

    // 3. Write new file
    let new_file = mount_dir.join("new_note.txt");
    fs::write(&new_file, b"brand new content in fuse").unwrap();

    // Verify readability through mount
    let read_back = fs::read_to_string(&new_file).unwrap();
    assert_eq!(read_back, "brand new content in fuse");

    // 4. Overwrite existing file in-place
    let hello_file = mount_dir.join("hello.txt");
    fs::write(&hello_file, b"Updated hello content").unwrap();
    let read_updated = fs::read_to_string(&hello_file).unwrap();
    assert_eq!(read_updated, "Updated hello content");

    // 5. Simulate editor atomic save (write to temp file then rename over target)
    let temp_edit = mount_dir.join("new_note.txt.tmp");
    fs::write(&temp_edit, b"Editor atomic save content").unwrap();
    fs::rename(&temp_edit, &new_file).unwrap();
    let read_renamed = fs::read_to_string(&new_file).unwrap();
    assert_eq!(read_renamed, "Editor atomic save content");

    // 6. Unmount
    drop(session);
    let _ = unmount_fuse_target(&mount_dir);

    // 7. Verify that vault_dir has exactly 2 files and decrypts to modified content
    let vault_files = collect_vault_files(&vault_dir);
    assert_eq!(
        vault_files.len(),
        2,
        "Should have exactly 2 files (no orphans from rename/overwrite)"
    );

    let creds = Credentials::new().with_password(password.to_vec());
    let mut decrypted_map = HashMap::new();
    for vf in &vault_files {
        let mut content = Vec::new();
        let f = File::open(vf).unwrap();
        let reader = BufReader::new(f);
        let header = decrypt_header_with_credentials(reader, &creds).unwrap();
        let orig_name = header.original_name.clone();
        let mut h = header;
        h.decrypt_payload(&mut content).unwrap();
        decrypted_map.insert(orig_name, String::from_utf8(content).unwrap());
    }

    assert_eq!(
        decrypted_map.get("hello.txt").unwrap(),
        "Updated hello content"
    );
    assert_eq!(
        decrypted_map.get("new_note.txt").unwrap(),
        "Editor atomic save content"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_fuse_age_vault_lifecycle() {
    if !has_fuse_support() {
        return;
    }

    let temp_dir = std::env::temp_dir().join(format!(
        "valv_fuse_age_test_{}",
        rand::rng().random::<u32>()
    ));
    let vault_dir = temp_dir.join("vault");
    let mount_dir = temp_dir.join("mount");
    fs::create_dir_all(&vault_dir).unwrap();
    fs::create_dir_all(&mount_dir).unwrap();

    let key = age::x25519::Identity::generate();
    let pubkey = key.to_public().to_string();
    let key_file = temp_dir.join("key.txt");
    fs::write(
        &key_file,
        format!("{}\n", key.to_string().expose_secret()),
    )
    .unwrap();

    let file_path = vault_dir.join("secret-x.age");
    let mut out = BufWriter::new(File::create(&file_path).unwrap());
    let recips = crate::crypto::load_recipients(std::slice::from_ref(&pubkey), &[]).unwrap();
    encrypt_stream_unified(
        &mut Cursor::new(b"Age Secret Content"),
        &mut out,
        "secret.txt",
        &EncryptionMethod::AgeRecipients(&recips),
    )
    .unwrap();
    drop(out);

    let fs = ValvFuseFs::new(
        &vault_dir,
        None,
        VaultFormat::Age,
        1000,
        vec![pubkey],
        vec![],
        vec![key_file],
        None,
    )
    .expect("ValvFuseFs creation");

    let options = vec![MountOption::FSName("valv_age_test".to_string())];

    let session = match fuser::spawn_mount2(fs, &mount_dir, &options) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Skipping test: spawn_mount2 failed: {}", e);
            let _ = fs::remove_dir_all(&temp_dir);
            return;
        }
    };

    let mut read_success = false;
    for _ in 0..50 {
        if let Ok(content) = fs::read_to_string(mount_dir.join("secret.txt")) {
            assert_eq!(content, "Age Secret Content");
            read_success = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(read_success, "Should read secret.txt via Age FUSE");

    drop(session);
    let _ = unmount_fuse_target(&mount_dir);
    let _ = fs::remove_dir_all(&temp_dir);
}
