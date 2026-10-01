pub mod manifest;
pub mod mount;
pub mod paths;
pub mod session;
pub mod sync;
pub mod thumbnail;

pub use manifest::{create_encrypted_manifest, save_encrypted_manifest, write_encrypted_manifest_bytes};
pub use mount::{mount_vault, mount_vault_with_credentials};
pub use paths::{
    clean_empty_dirs_up_to, collect_plain_files, collect_vault_files, generate_random_filename,
    get_suffix_for_path, get_suffix_for_path_and_format, get_thumbnail_valv_name,
    is_thumbnail_valv_file, is_valv_file, sanitize_filename,
};
pub use session::{get_mount_dir, is_process_alive, list_mounts, ActiveMount, SessionFileEntry, ValvSession};
pub use sync::{preserve_unsynced_dirs, run_sync_daemon_with_credentials, sync_file_to_vault, unmount_vault};
pub use thumbnail::{create_thumbnail_file_unified, generate_thumbnail};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        encrypt_stream, encrypt_stream_unified, Credentials, EncryptionMethod, VaultFormat,
    };
    use rand::RngExt;
    use std::fs::{self, File};
    use std::io::{BufReader, BufWriter, Cursor};
    use std::path::Path;
    use std::process::Command;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_filename_suffixes() {
        assert_eq!(get_suffix_for_path(Path::new("test.jpg")), "-i.valv");
        assert_eq!(get_suffix_for_path(Path::new("anim.gif")), "-g.valv");
        assert_eq!(get_suffix_for_path(Path::new("video.mp4")), "-v.valv");
        assert_eq!(get_suffix_for_path(Path::new("doc.txt")), "-x.valv");
        assert_eq!(get_suffix_for_path(Path::new("unknown.xyz")), "-i.valv");

        assert_eq!(
            get_suffix_for_path_and_format(Path::new("test.jpg"), VaultFormat::Age),
            "-i.age"
        );
        assert_eq!(
            get_suffix_for_path_and_format(Path::new("video.mp4"), VaultFormat::Age),
            "-v.age"
        );
        assert_eq!(
            get_suffix_for_path_and_format(Path::new("file.pdf"), VaultFormat::Age),
            "-x.age"
        );
    }

    #[test]
    fn test_get_thumbnail_valv_name() {
        assert_eq!(
            get_thumbnail_valv_name("abc123xyz-i.valv"),
            Some("abc123xyz-t.valv".to_string())
        );
        assert_eq!(
            get_thumbnail_valv_name("abc123xyz-g.valv"),
            Some("abc123xyz-t.valv".to_string())
        );
        assert_eq!(
            get_thumbnail_valv_name("abc123xyz-v.valv"),
            Some("abc123xyz-t.valv".to_string())
        );
        assert_eq!(get_thumbnail_valv_name("abc123xyz-x.valv"), None);

        assert_eq!(
            get_thumbnail_valv_name("abc123xyz-i.age"),
            Some("abc123xyz-t.age".to_string())
        );
        assert_eq!(
            get_thumbnail_valv_name("abc123xyz-v.age"),
            Some("abc123xyz-t.age".to_string())
        );
    }

    #[test]
    fn test_thumbnail_suffix_detection() {
        assert!(is_thumbnail_valv_file(Path::new("abc-t.valv")));
        assert!(is_thumbnail_valv_file(Path::new("abc-t.age")));
        assert!(!is_thumbnail_valv_file(Path::new("abc-i.valv")));
        assert!(!is_thumbnail_valv_file(Path::new("abc-x.valv")));
    }

    #[test]
    fn test_mount_unmount_lifecycle() {
        let temp_dir =
            std::env::temp_dir().join(format!("valv_test_mount_{}", rand::rng().random::<u32>()));
        let vault_dir = temp_dir.join("vault");
        let mount_dir = temp_dir.join("mount");
        fs::create_dir_all(&vault_dir).unwrap();

        let password = b"VaultPass123";
        let file_path = vault_dir.join("testfile-x.valv");
        let mut out = BufWriter::new(File::create(&file_path).unwrap());
        encrypt_stream(
            &mut Cursor::new(b"Hello from vault"),
            &mut out,
            password,
            "hello.txt",
            1000,
        )
        .unwrap();

        let current_pid = std::process::id();
        mount_vault(
            &vault_dir,
            &mount_dir,
            password,
            Some(current_pid),
            false,
            1000,
        )
        .expect("Mount should succeed");

        assert!(mount_dir.join("hello.txt").exists());
        let decrypted_content = fs::read_to_string(mount_dir.join("hello.txt")).unwrap();
        assert_eq!(decrypted_content, "Hello from vault");

        unmount_vault(&mount_dir).expect("Unmount should succeed");
        assert!(!mount_dir.exists());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_age_vault_mount_unmount_lifecycle() {
        let temp_dir = std::env::temp_dir().join(format!(
            "valv_test_age_mount_{}",
            rand::rng().random::<u32>()
        ));
        let vault_dir = temp_dir.join("vault");
        let mount_dir = temp_dir.join("mount");
        fs::create_dir_all(&vault_dir).unwrap();

        let key = age::x25519::Identity::generate();
        let pubkey = key.to_public();
        let file_path = vault_dir.join("testfile-x.age");
        let mut out = BufWriter::new(File::create(&file_path).unwrap());
        let recipients = vec![Box::new(pubkey) as Box<dyn age::Recipient + Send>];
        encrypt_stream_unified(
            &mut Cursor::new(b"Hello from age vault"),
            &mut out,
            "age_hello.txt",
            &EncryptionMethod::AgeRecipients(&recipients),
        )
        .unwrap();
        drop(out);

        let creds = Credentials::new().with_identities(vec![Box::new(key)]);
        let current_pid = std::process::id();
        mount_vault_with_credentials(
            &vault_dir,
            &mount_dir,
            &creds,
            Some(current_pid),
            false,
            1000,
            VaultFormat::Age,
            &recipients,
            &[],
            &[],
        )
        .expect("Age mount should succeed");

        assert!(mount_dir.join("age_hello.txt").exists());
        let decrypted_content = fs::read_to_string(mount_dir.join("age_hello.txt")).unwrap();
        assert_eq!(decrypted_content, "Hello from age vault");

        unmount_vault(&mount_dir).expect("Unmount should succeed");
        assert!(!mount_dir.exists());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_nested_vault_mount_and_pasting_directories() {
        let temp_dir = std::env::temp_dir().join(format!(
            "valv_test_nested_vault_{}",
            rand::rng().random::<u32>()
        ));
        let vault_dir = temp_dir.join("vault");
        let mount_dir = temp_dir.join("mount");
        fs::create_dir_all(&vault_dir).unwrap();

        let password = b"VaultPass123";
        let nested_vault_dir = vault_dir.join("docs/work");
        fs::create_dir_all(&nested_vault_dir).unwrap();

        let file_path = nested_vault_dir.join("project-x.valv");
        let mut out = BufWriter::new(File::create(&file_path).unwrap());
        encrypt_stream(
            &mut Cursor::new(b"Work Project Plan"),
            &mut out,
            password,
            "plan.txt",
            1000,
        )
        .unwrap();

        let current_pid = std::process::id();
        mount_vault(
            &vault_dir,
            &mount_dir,
            password,
            Some(current_pid),
            false,
            1000,
        )
        .expect("Mount should succeed");

        let mounted_file = mount_dir.join("docs/work/plan.txt");
        assert!(mounted_file.exists());
        let content = fs::read_to_string(&mounted_file).unwrap();
        assert_eq!(content, "Work Project Plan");

        unmount_vault(&mount_dir).expect("Unmount should succeed");
        assert!(!mount_dir.exists());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_list_mounts() {
        let mounts = list_mounts();
        let _ = mounts.len();
    }

    #[test]
    fn test_unmount_by_vault_dir() {
        let temp_dir =
            std::env::temp_dir().join(format!("valv_test_vdir_{}", rand::rng().random::<u32>()));
        let vault_dir = temp_dir.join("vault");
        fs::create_dir_all(&vault_dir).unwrap();

        let password = b"VaultPass123";
        let file_path = vault_dir.join("testfile-x.valv");
        let mut out = BufWriter::new(File::create(&file_path).unwrap());
        encrypt_stream(
            &mut Cursor::new(b"Hello from vault"),
            &mut out,
            password,
            "hello.txt",
            1000,
        )
        .unwrap();

        let current_pid = std::process::id();
        let mount_dir = get_mount_dir(&vault_dir, Some(current_pid), None);
        mount_vault(
            &vault_dir,
            &mount_dir,
            password,
            Some(current_pid),
            false,
            1000,
        )
        .expect("Mount should succeed");

        assert!(mount_dir.join("hello.txt").exists());

        unmount_vault(&vault_dir).expect("Unmount by vault dir should succeed");
        assert!(!mount_dir.exists());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_mount_ignores_thumbnails() {
        let temp_dir =
            std::env::temp_dir().join(format!("valv_test_thumb_{}", rand::rng().random::<u32>()));
        let vault_dir = temp_dir.join("vault");
        let mount_dir = temp_dir.join("mount");
        fs::create_dir_all(&vault_dir).unwrap();

        let password = b"VaultPass123";
        let img_valv = vault_dir.join("abc123-i.valv");
        let mut out_img = BufWriter::new(File::create(&img_valv).unwrap());
        encrypt_stream(
            &mut Cursor::new(b"FULL_RESOLUTION_IMAGE_DATA_12345"),
            &mut out_img,
            password,
            "photo.jpg",
            1000,
        )
        .unwrap();

        let thumb_valv = vault_dir.join("abc123-t.valv");
        let mut out_thumb = BufWriter::new(File::create(&thumb_valv).unwrap());
        encrypt_stream(
            &mut Cursor::new(b"THUMBNAIL_PREVIEW"),
            &mut out_thumb,
            password,
            "photo.jpg",
            1000,
        )
        .unwrap();

        let current_pid = std::process::id();
        mount_vault(
            &vault_dir,
            &mount_dir,
            password,
            Some(current_pid),
            false,
            1000,
        )
        .expect("Mount should succeed");

        let decrypted_img = mount_dir.join("photo.jpg");
        assert!(decrypted_img.exists());
        let content = fs::read(&decrypted_img).unwrap();
        assert_eq!(content, b"FULL_RESOLUTION_IMAGE_DATA_12345");

        unmount_vault(&mount_dir).expect("Unmount should succeed");
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_thumbnail_generation_and_auto_mount() {
        let has_ffmpeg = Command::new("ffmpeg").arg("-version").output().is_ok();
        let has_convert = Command::new("convert").arg("-version").output().is_ok();
        if !has_ffmpeg && !has_convert {
            return;
        }

        let temp_dir = std::env::temp_dir().join(format!(
            "valv_test_thumb_gen_{}",
            rand::rng().random::<u32>()
        ));
        let vault_dir = temp_dir.join("vault");
        let mount_dir = temp_dir.join("mount");
        fs::create_dir_all(&vault_dir).unwrap();

        let src_img = temp_dir.join("sample.png");
        let png_1x1_data: [u8; 67] = [
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48,
            0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00,
            0x00, 0x1F, 0x15, 0xC4, 0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x78,
            0x9C, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00,
            0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
        ];
        fs::write(&src_img, png_1x1_data).unwrap();

        let password = b"VaultPass123";
        let img_valv = vault_dir.join("abc123xyz-i.valv");
        let mut out_img = BufWriter::new(File::create(&img_valv).unwrap());
        encrypt_stream(
            &mut BufReader::new(File::open(&src_img).unwrap()),
            &mut out_img,
            password,
            "test.png",
            1000,
        )
        .unwrap();

        let expected_thumb_valv = vault_dir.join("abc123xyz-t.valv");
        assert!(!expected_thumb_valv.exists());

        let current_pid = std::process::id();
        mount_vault(
            &vault_dir,
            &mount_dir,
            password,
            Some(current_pid),
            false,
            1000,
        )
        .expect("Mount should succeed");

        assert!(expected_thumb_valv.exists());

        let mut decrypted_thumb = Vec::new();
        crate::crypto::decrypt_file_to(&expected_thumb_valv, password, &mut decrypted_thumb)
            .expect("Decrypt thumbnail");
        assert_eq!(&decrypted_thumb[..2], &[0xff, 0xd8]);

        unmount_vault(&mount_dir).expect("Unmount should succeed");
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_sanitize_filename() {
        assert_eq!(sanitize_filename("test.txt"), "test.txt");
        assert_eq!(sanitize_filename("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_filename("/etc/shadow"), "shadow");
        assert_eq!(
            sanitize_filename("C:\\Windows\\system32\\cmd.exe"),
            "cmd.exe"
        );
        assert_eq!(sanitize_filename("."), "decrypted_file");
        assert_eq!(sanitize_filename(".."), "decrypted_file");
        assert_eq!(sanitize_filename(""), "decrypted_file");
        assert_eq!(sanitize_filename("   "), "decrypted_file");
        assert_eq!(sanitize_filename("foo\0bar"), "decrypted_file");
    }

    #[test]
    fn test_unsynced_subdirectory_preserved() {
        let temp_dir =
            std::env::temp_dir().join(format!("valv_test_sub_{}", rand::rng().random::<u32>()));
        let vault_dir = temp_dir.join("vault");
        let mount_dir = temp_dir.join("mount");
        fs::create_dir_all(&vault_dir).unwrap();

        let password = b"VaultPass123";
        let file_path = vault_dir.join("testfile-x.valv");
        let mut out = BufWriter::new(File::create(&file_path).unwrap());
        encrypt_stream(
            &mut Cursor::new(b"Hello"),
            &mut out,
            password,
            "hello.txt",
            1000,
        )
        .unwrap();

        let current_pid = std::process::id();
        mount_vault(
            &vault_dir,
            &mount_dir,
            password,
            Some(current_pid),
            false,
            1000,
        )
        .expect("Mount should succeed");

        let user_folder = mount_dir.join("MyFolder");
        fs::create_dir_all(&user_folder).unwrap();
        fs::write(user_folder.join("notes.txt"), b"important unsynced data").unwrap();

        unmount_vault(&mount_dir).expect("Unmount should succeed");

        assert!(vault_dir.join("MyFolder/notes.txt").exists());
        let preserved_data = fs::read_to_string(vault_dir.join("MyFolder/notes.txt")).unwrap();
        assert_eq!(preserved_data, "important unsynced data");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_age_vault_manifest_lifecycle_and_reencryption() {
        let temp_dir = std::env::temp_dir().join(format!("valv_manifest_reenc_{}", rand::rng().random::<u32>()));
        let vault_dir = temp_dir.join("vault");
        let mount_dir = temp_dir.join("mount");
        fs::create_dir_all(&vault_dir).unwrap();

        let key1 = age::x25519::Identity::generate();
        let pubkey1 = key1.to_public();

        let key2 = age::x25519::Identity::generate();
        let pubkey2 = key2.to_public();

        let manifest_content = format!("recipients = [\"{}\"]\n", pubkey1);
        fs::write(vault_dir.join(".age_vault.toml"), manifest_content).unwrap();

        let file_path = vault_dir.join("secret-x.age");
        let mut out = BufWriter::new(File::create(&file_path).unwrap());
        let recips1 = vec![Box::new(pubkey1.clone()) as Box<dyn age::Recipient + Send>];
        encrypt_stream_unified(
            &mut Cursor::new(b"Initial Secret Document"),
            &mut out,
            "secret.txt",
            &EncryptionMethod::AgeRecipients(&recips1),
        )
        .unwrap();
        drop(out);

        let creds2 = Credentials::new().with_identities(vec![Box::new(key2.clone())]);
        let mut check_fail = Vec::new();
        assert!(crate::crypto::decrypt_file_with_credentials_to(&file_path, &creds2, &mut check_fail).is_err());

        let v_dir = vault_dir.clone();
        let m_dir = mount_dir.clone();
        let key1_clone = key1.clone();
        let r1 = vec![Box::new(pubkey1.clone()) as Box<dyn age::Recipient + Send>];
        let p1_str = pubkey1.to_string();

        let daemon_handle = thread::spawn(move || {
            let c1 = Credentials::new().with_identities(vec![Box::new(key1_clone)]);
            mount_vault_with_credentials(
                &v_dir,
                &m_dir,
                &c1,
                None,
                true,
                1000,
                VaultFormat::Age,
                &r1,
                &[],
                &[p1_str],
            )
        });

        for _ in 0..50 {
            if mount_dir.join("secret.txt").exists() && mount_dir.join(".age_vault.toml").exists() {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }

        assert!(mount_dir.join("secret.txt").exists());
        assert!(mount_dir.join(".age_vault.toml").exists());

        let updated_manifest = format!("recipients = [\"{}\", \"{}\"]\n", pubkey1, pubkey2);
        fs::write(mount_dir.join(".age_vault.toml"), updated_manifest).unwrap();

        thread::sleep(Duration::from_millis(1500));

        unmount_vault(&mount_dir).expect("Unmount should succeed");
        daemon_handle.join().expect("Daemon thread joined").expect("Daemon run succeeded");

        assert!(vault_dir.join(".age_vault.toml.age").exists());
        assert!(!vault_dir.join(".age_vault.toml").exists());

        let mut check_success = Vec::new();
        let orig_name = crate::crypto::decrypt_file_with_credentials_to(&file_path, &creds2, &mut check_success)
            .expect("Decryption by newly added recipient should now succeed after re-encryption");
        assert_eq!(orig_name, "secret.txt");
        assert_eq!(check_success, b"Initial Secret Document");

        let (decrypted_manifest, _, _) = crate::config::AgeVaultManifest::load_from_dir_with_credentials(&vault_dir, &creds2)
            .unwrap()
            .expect("Manifest should decrypt with key2");
        assert_eq!(decrypted_manifest.recipients.len(), 2);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_mount_fails_when_encrypted_manifest_cannot_be_decrypted() {
        let temp_dir = std::env::temp_dir().join(format!("valv_manifest_fail_{}", rand::rng().random::<u32>()));
        let vault_dir = temp_dir.join("vault");
        let mount_dir = temp_dir.join("mount");
        fs::create_dir_all(&vault_dir).unwrap();

        let key_owner = age::x25519::Identity::generate();
        let pubkey_owner = key_owner.to_public();

        let key_stranger = age::x25519::Identity::generate();

        let manifest_content = format!("recipients = [\"{}\"]\n", pubkey_owner);
        let plain_manifest = temp_dir.join(".age_vault.toml");
        fs::write(&plain_manifest, &manifest_content).unwrap();

        let recips = vec![Box::new(pubkey_owner) as Box<dyn age::Recipient + Send>];
        let creds_empty = Credentials::new();
        save_encrypted_manifest(&plain_manifest, &vault_dir, VaultFormat::Age, &recips, &creds_empty, 1000)
            .expect("Save encrypted manifest should succeed");

        assert!(vault_dir.join(".age_vault.toml.age").exists());
        assert!(!vault_dir.join(".age_vault.toml").exists());

        let creds_stranger = Credentials::new().with_identities(vec![Box::new(key_stranger)]);
        let mount_res = mount_vault_with_credentials(
            &vault_dir,
            &mount_dir,
            &creds_stranger,
            None,
            false,
            1000,
            VaultFormat::Age,
            &[],
            &[],
            &[],
        );

        assert!(mount_res.is_err(), "Mount must fail when manifest cannot be decrypted");
        assert!(!mount_dir.exists(), "Mount directory should not exist on failed mount");

        let m_dir = mount_dir.clone();
        let v_dir = vault_dir.clone();
        let daemon_handle = thread::spawn(move || {
            let creds_owner = Credentials::new().with_identities(vec![Box::new(key_owner)]);
            mount_vault_with_credentials(
                &v_dir,
                &m_dir,
                &creds_owner,
                None,
                true,
                1000,
                VaultFormat::Age,
                &[],
                &[],
                &[],
            )
        });

        for _ in 0..50 {
            if mount_dir.join(".age_vault.toml").exists() {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }

        assert!(mount_dir.join(".age_vault.toml").exists(), "Decrypted manifest should be visible in mount_dir");
        unmount_vault(&mount_dir).expect("Unmount should succeed");
        daemon_handle.join().expect("Daemon thread joined").expect("Daemon run succeeded");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_create_encrypted_manifest_and_mount() {
        let temp_dir = std::env::temp_dir().join(format!("valv_init_test_{}", rand::rng().random::<u32>()));
        let vault_dir = temp_dir.join("vault");
        let mount_dir = temp_dir.join("mount");
        fs::create_dir_all(&vault_dir).unwrap();

        let key = age::x25519::Identity::generate();
        let pubkey = key.to_public();

        let manifest = crate::config::AgeVaultManifest {
            recipients: vec![pubkey.to_string()],
            recipients_files: Vec::new(),
        };
        let recips = vec![Box::new(pubkey.clone()) as Box<dyn age::Recipient + Send>];
        let creds = Credentials::new();

        let created_path = create_encrypted_manifest(&vault_dir, &manifest, VaultFormat::Age, &recips, &creds, 1000)
            .expect("create_encrypted_manifest should succeed");

        assert_eq!(created_path, vault_dir.join(".age_vault.toml.age"));
        assert!(created_path.exists());
        assert!(!vault_dir.join(".age_vault.toml").exists());

        // Verify that it loads and decrypts with key
        let creds_with_key = Credentials::new().with_identities(vec![Box::new(key.clone())]);
        let loaded = crate::config::AgeVaultManifest::load_from_dir_with_credentials(&vault_dir, &creds_with_key)
            .expect("Should load from dir with credentials");
        assert!(loaded.is_some());
        let (loaded_manifest, _, _) = loaded.unwrap();
        assert_eq!(loaded_manifest.recipients, vec![pubkey.to_string()]);

        // Mount vault and verify decrypted manifest
        let v_dir = vault_dir.clone();
        let m_dir = mount_dir.clone();
        let key_clone = key.clone();
        let daemon_handle = thread::spawn(move || {
            let creds_with_key = Credentials::new().with_identities(vec![Box::new(key_clone)]);
            mount_vault_with_credentials(
                &v_dir,
                &m_dir,
                &creds_with_key,
                None,
                true,
                1000,
                VaultFormat::Age,
                &[],
                &[],
                &[],
            )
        });

        for _ in 0..50 {
            if mount_dir.join(".age_vault.toml").exists() {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }

        assert!(mount_dir.join(".age_vault.toml").exists());
        unmount_vault(&mount_dir).expect("Unmount should succeed");
        daemon_handle.join().expect("Daemon thread joined").expect("Daemon succeeded");

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
