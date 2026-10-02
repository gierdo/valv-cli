use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize, Serialize, Default, Clone, PartialEq, Eq)]
pub struct AgeVaultManifest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identity_files: Vec<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recipients: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipients_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recipients_files: Vec<PathBuf>,
}

impl AgeVaultManifest {
    pub const FILE_NAMES: &'static [&'static str] = &[
        ".age_vault.toml.age",
        "age_vault.toml.age",
        ".age_vault.toml.valv",
        "age_vault.toml.valv",
        ".age_vault.toml",
        "age_vault.toml",
    ];

    pub fn resolve_recipients(&self) -> (Vec<String>, Vec<PathBuf>) {
        use std::str::FromStr;

        let mut recipient_strs = Vec::new();
        let mut recipient_file_paths = Vec::new();

        let mut direct_recipients = Vec::new();
        if let Some(ref r) = self.recipient {
            direct_recipients.push(r.clone());
        }
        for r in &self.recipients {
            direct_recipients.push(r.clone());
        }

        for r in direct_recipients {
            let trimmed = r.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.starts_with("AGE-SECRET-KEY-1") {
                if let Ok(id) = age::x25519::Identity::from_str(trimmed) {
                    let pk = id.to_public().to_string();
                    if !recipient_strs.contains(&pk) {
                        recipient_strs.push(pk);
                    }
                }
            } else if trimmed.starts_with("age1")
                || trimmed.starts_with("ssh-ed25519 ")
                || trimmed.starts_with("ssh-rsa ")
                || trimmed.starts_with("ecdsa-sha2-")
            {
                if !recipient_strs.contains(&trimmed.to_string()) {
                    recipient_strs.push(trimmed.to_string());
                }
            } else {
                let p = expand_tilde(Path::new(trimmed));
                let derived = crate::crypto::extract_recipients_from_identity_file(&p);
                for d in derived {
                    if !recipient_strs.contains(&d) {
                        recipient_strs.push(d);
                    }
                }
            }
        }

        if let Some(ref rf) = self.recipients_file {
            let expanded = expand_tilde(rf);
            if !recipient_file_paths.contains(&expanded) {
                recipient_file_paths.push(expanded);
            }
        }
        for rf in &self.recipients_files {
            let expanded = expand_tilde(rf);
            if !recipient_file_paths.contains(&expanded) {
                recipient_file_paths.push(expanded);
            }
        }

        let mut identity_entries = Vec::new();
        if let Some(ref id) = self.identity {
            identity_entries.push(id.clone());
        }
        for id in &self.identities {
            identity_entries.push(id.clone());
        }

        for id_entry in identity_entries {
            let trimmed = id_entry.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.starts_with("AGE-SECRET-KEY-1") {
                if let Ok(id) = age::x25519::Identity::from_str(trimmed) {
                    let pk = id.to_public().to_string();
                    if !recipient_strs.contains(&pk) {
                        recipient_strs.push(pk);
                    }
                }
            } else if trimmed.starts_with("age1")
                || trimmed.starts_with("ssh-ed25519 ")
                || trimmed.starts_with("ssh-rsa ")
                || trimmed.starts_with("ecdsa-sha2-")
            {
                if !recipient_strs.contains(&trimmed.to_string()) {
                    recipient_strs.push(trimmed.to_string());
                }
            } else {
                let p = expand_tilde(Path::new(trimmed));
                let derived = crate::crypto::extract_recipients_from_identity_file(&p);
                for d in derived {
                    if !recipient_strs.contains(&d) {
                        recipient_strs.push(d);
                    }
                }
            }
        }

        let mut id_files = Vec::new();
        if let Some(ref idf) = self.identity_file {
            id_files.push(idf.clone());
        }
        for idf in &self.identity_files {
            id_files.push(idf.clone());
        }
        for idf in id_files {
            let p = expand_tilde(&idf);
            let derived = crate::crypto::extract_recipients_from_identity_file(&p);
            for d in derived {
                if !recipient_strs.contains(&d) {
                    recipient_strs.push(d);
                }
            }
        }

        (recipient_strs, recipient_file_paths)
    }

    pub fn find_in_dir(dir: &Path) -> Option<PathBuf> {
        for name in Self::FILE_NAMES {
            let path = dir.join(name);
            if path.is_file() {
                return Some(path);
            }
        }
        None
    }

    pub fn load_from_file_with_credentials(
        path: &Path,
        credentials: &crate::crypto::Credentials,
    ) -> Result<(Self, String), String> {
        // 1. Try reading as plaintext TOML first (if unencrypted manifest exists)
        if let Ok(content) = fs::read_to_string(path)
            && let Ok(manifest) = toml::from_str::<Self>(&content)
        {
            return Ok((manifest, content));
        }

        // 2. Decrypt as encrypted file using provided credentials
        let mut decrypted = Vec::new();
        match crate::crypto::decrypt_file_with_credentials_to(path, credentials, &mut decrypted) {
            Ok(_) => {
                let content = String::from_utf8(decrypted)
                    .map_err(|e| format!("Manifest decrypted but is not valid UTF-8: {}", e))?;
                let manifest: Self = toml::from_str(&content)
                    .map_err(|e| format!("Manifest decrypted but failed to parse TOML: {}", e))?;
                Ok((manifest, content))
            }
            Err(e) => Err(format!(
                "Failed to decrypt manifest {}: {:?}",
                path.display(),
                e
            )),
        }
    }

    pub fn load_from_dir_with_credentials(
        dir: &Path,
        credentials: &crate::crypto::Credentials,
    ) -> Result<Option<(Self, PathBuf, String)>, String> {
        if let Some(path) = Self::find_in_dir(dir) {
            let (manifest, content) = Self::load_from_file_with_credentials(&path, credentials)?;
            Ok(Some((manifest, path, content)))
        } else {
            Ok(None)
        }
    }

    pub fn load_from_dir(dir: &Path) -> Result<Option<(Self, PathBuf)>, String> {
        let creds = crate::crypto::Credentials::new();
        Self::load_from_dir_with_credentials(dir, &creds)
            .map(|opt| opt.map(|(manifest, path, _)| (manifest, path)))
    }
}

pub fn is_manifest_file(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    AgeVaultManifest::FILE_NAMES.contains(&name)
}

#[derive(Debug, Deserialize, Default, Clone, PartialEq, Eq)]
pub struct ValvConfig {
    #[serde(default)]
    pub age: AgeConfig,
    #[serde(default)]
    pub identity: Option<PathBuf>,
    #[serde(default)]
    pub identities: Vec<PathBuf>,
}

#[derive(Debug, Deserialize, Default, Clone, PartialEq, Eq)]
pub struct AgeConfig {
    /// Age identity file path or SSH private key
    #[serde(default)]
    pub identity: Option<PathBuf>,
    /// Multiple age identity file paths
    #[serde(default)]
    pub identities: Vec<PathBuf>,
    /// Single recipient public key
    #[serde(default)]
    pub recipient: Option<String>,
    /// Default recipient public keys (e.g. age1...)
    #[serde(default)]
    pub recipients: Vec<String>,
    /// Single recipient file
    #[serde(default)]
    pub recipients_file: Option<PathBuf>,
    /// Default recipient files
    #[serde(default)]
    pub recipients_files: Vec<PathBuf>,
}

impl ValvConfig {
    pub fn default_config_path() -> Option<PathBuf> {
        if let Some(cfg_env) = std::env::var_os("VALV_CONFIG") {
            return Some(PathBuf::from(cfg_env));
        }
        if let Some(xdg_cfg) = std::env::var_os("XDG_CONFIG_HOME") {
            return Some(PathBuf::from(xdg_cfg).join("valv").join("config.toml"));
        }
        if let Some(home) = std::env::var_os("HOME") {
            return Some(
                PathBuf::from(home)
                    .join(".config")
                    .join("valv")
                    .join("config.toml"),
            );
        }
        None
    }

    pub fn load_from_str(toml_str: &str) -> Result<Self, String> {
        toml::from_str(toml_str).map_err(|e| format!("Failed to parse configuration: {}", e))
    }

    pub fn load_from_path(path: &Path) -> Result<Self, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config file {}: {}", path.display(), e))?;
        Self::load_from_str(&content)
    }

    pub fn load(custom_path: Option<&Path>) -> Result<Self, String> {
        if let Some(path) = custom_path {
            return Self::load_from_path(path);
        }
        if let Some(default_path) = Self::default_config_path()
            && default_path.exists()
        {
            return Self::load_from_path(&default_path);
        }
        Ok(Self::default())
    }

    pub fn resolve_identities(&self, cli_identities: &[PathBuf]) -> Vec<PathBuf> {
        if !cli_identities.is_empty() {
            return cli_identities.iter().map(|p| expand_tilde(p)).collect();
        }
        let mut ids = Vec::new();
        if let Some(ref id) = self.identity {
            ids.push(expand_tilde(id));
        }
        for id in &self.identities {
            ids.push(expand_tilde(id));
        }
        if let Some(ref id) = self.age.identity {
            ids.push(expand_tilde(id));
        }
        for id in &self.age.identities {
            ids.push(expand_tilde(id));
        }
        if ids.is_empty() {
            for path in sops_default_identity_paths() {
                if path.exists() {
                    ids.push(path);
                    break;
                }
            }
        }
        ids
    }

    pub fn resolve_recipients(&self, cli_recipients: &[String]) -> Vec<String> {
        if !cli_recipients.is_empty() {
            return cli_recipients.to_vec();
        }
        let mut recips = Vec::new();
        if let Some(ref r) = self.age.recipient
            && !recips.contains(r)
        {
            recips.push(r.clone());
        }
        for r in &self.age.recipients {
            if !recips.contains(r) {
                recips.push(r.clone());
            }
        }
        recips
    }

    pub fn resolve_recipients_files(&self, cli_recipients_files: &[PathBuf]) -> Vec<PathBuf> {
        if !cli_recipients_files.is_empty() {
            return cli_recipients_files
                .iter()
                .map(|p| expand_tilde(p))
                .collect();
        }
        let mut files = Vec::new();
        if let Some(ref f) = self.age.recipients_file {
            let exp = expand_tilde(f);
            if !files.contains(&exp) {
                files.push(exp);
            }
        }
        for f in &self.age.recipients_files {
            let exp = expand_tilde(f);
            if !files.contains(&exp) {
                files.push(exp);
            }
        }
        files
    }
}

pub fn sops_default_identity_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Some(key_file) = std::env::var_os("SOPS_AGE_KEY_FILE") {
        paths.push(PathBuf::from(key_file));
    }

    if let Some(xdg_cfg) = std::env::var_os("XDG_CONFIG_HOME") {
        paths.push(
            PathBuf::from(xdg_cfg)
                .join("sops")
                .join("age")
                .join("keys.txt"),
        );
    }

    if let Some(home) = std::env::var_os("HOME") {
        paths.push(
            PathBuf::from(&home)
                .join(".config")
                .join("sops")
                .join("age")
                .join("keys.txt"),
        );
        #[cfg(target_os = "macos")]
        {
            paths.push(
                PathBuf::from(&home)
                    .join("Library")
                    .join("Application Support")
                    .join("sops")
                    .join("age")
                    .join("keys.txt"),
            );
        }
    }

    #[cfg(windows)]
    {
        if let Some(appdata) = std::env::var_os("APPDATA") {
            paths.push(
                PathBuf::from(appdata)
                    .join("sops")
                    .join("age")
                    .join("keys.txt"),
            );
        }
    }

    paths
}

pub fn expand_tilde(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(stripped) = s.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(stripped);
        }
    } else if s == "~"
        && let Some(home) = std::env::var_os("HOME")
    {
        return PathBuf::from(home);
    }
    path.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sops_default_identity_paths() {
        let paths = sops_default_identity_paths();
        assert!(!paths.is_empty());
        let has_sops = paths.iter().any(|p| p.to_string_lossy().contains("sops"));
        assert!(has_sops);
    }

    #[test]
    fn test_sops_identity_fallback() {
        let temp_dir =
            std::env::temp_dir().join(format!("valv_sops_test_{}", rand::random::<u32>()));
        fs::create_dir_all(&temp_dir).unwrap();

        let sops_key = temp_dir.join("keys.txt");
        fs::write(&sops_key, b"AGE-SECRET-KEY-1...").unwrap();

        // When SOPS_AGE_KEY_FILE is set to an existing key file
        unsafe {
            std::env::set_var("SOPS_AGE_KEY_FILE", &sops_key);
        }

        let cfg = ValvConfig::default();
        let resolved = cfg.resolve_identities(&[]);
        assert_eq!(resolved, vec![sops_key.clone()]);

        // Cleanup env
        unsafe {
            std::env::remove_var("SOPS_AGE_KEY_FILE");
        }
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_parse_age_config() {
        let toml_data = r#"
[age]
identity = "~/.config/age/key.txt"
identities = ["/etc/age/backup_key.txt"]
recipients = ["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"]
recipients_files = ["~/.config/age/recipients.txt"]
"#;
        let cfg = ValvConfig::load_from_str(toml_data).unwrap();
        assert_eq!(
            cfg.age.identity,
            Some(PathBuf::from("~/.config/age/key.txt"))
        );
        assert_eq!(
            cfg.age.identities,
            vec![PathBuf::from("/etc/age/backup_key.txt")]
        );
        assert_eq!(
            cfg.age.recipients,
            vec!["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"]
        );
        assert_eq!(
            cfg.age.recipients_files,
            vec![PathBuf::from("~/.config/age/recipients.txt")]
        );

        let resolved_ids = cfg.resolve_identities(&[]);
        assert_eq!(resolved_ids.len(), 2);

        // CLI flag takes precedence over config
        let cli_override = vec![PathBuf::from("/custom/key.txt")];
        let resolved_override = cfg.resolve_identities(&cli_override);
        assert_eq!(resolved_override, vec![PathBuf::from("/custom/key.txt")]);
    }

    #[test]
    fn test_expand_tilde() {
        let home = std::env::var_os("HOME");
        if let Some(h) = home {
            let expanded = expand_tilde(Path::new("~/foo/bar.txt"));
            assert_eq!(expanded, PathBuf::from(h).join("foo/bar.txt"));
        }
    }

    #[test]
    fn test_age_vault_manifest_discovery() {
        let temp_dir =
            std::env::temp_dir().join(format!("valv_manifest_test_{}", rand::random::<u32>()));
        fs::create_dir_all(&temp_dir).unwrap();

        assert_eq!(AgeVaultManifest::find_in_dir(&temp_dir), None);

        let manifest_file = temp_dir.join(".age_vault.toml");
        fs::write(
            &manifest_file,
            b"recipients = [\"age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p\"]\n",
        )
        .unwrap();

        let found = AgeVaultManifest::find_in_dir(&temp_dir);
        assert_eq!(found, Some(manifest_file.clone()));

        let loaded = AgeVaultManifest::load_from_dir(&temp_dir).unwrap();
        assert!(loaded.is_some());
        let (manifest, path) = loaded.unwrap();
        assert_eq!(path, manifest_file);
        assert_eq!(
            manifest.recipients,
            vec!["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"]
        );

        assert!(is_manifest_file(&manifest_file));
        assert!(is_manifest_file(Path::new("age_vault.toml")));
        assert!(!is_manifest_file(Path::new("document.txt")));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_age_vault_manifest_resolve_recipients_identities() {
        use age::secrecy::ExposeSecret;
        let temp_dir =
            std::env::temp_dir().join(format!("valv_manifest_id_test_{}", rand::random::<u32>()));
        fs::create_dir_all(&temp_dir).unwrap();

        let key1 = age::x25519::Identity::generate();
        let pubkey1 = key1.to_public().to_string();
        let key2 = age::x25519::Identity::generate();
        let pubkey2 = key2.to_public().to_string();

        let key_file = temp_dir.join("key2.txt");
        fs::write(
            &key_file,
            format!(
                "# public key: {}\n{}\n",
                pubkey2,
                key2.to_string().expose_secret()
            ),
        )
        .unwrap();

        let toml_str = format!(
            "identity = \"{}\"\nidentities = [\"{}\"]\nrecipient = \"{}\"\n",
            key_file.display(),
            key1.to_string().expose_secret(),
            pubkey1
        );

        let manifest: AgeVaultManifest = toml::from_str(&toml_str).unwrap();
        let (resolved_recips, resolved_files) = manifest.resolve_recipients();

        assert!(resolved_recips.contains(&pubkey1));
        assert!(resolved_recips.contains(&pubkey2));
        assert_eq!(resolved_recips.len(), 2);
        assert!(resolved_files.is_empty());

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
