use std::fs;
use std::path::{Path, PathBuf};
use rand::RngExt;
use crate::crypto::VaultFormat;

pub fn get_suffix_for_path(path: &Path) -> &'static str {
    get_suffix_for_path_and_format(path, VaultFormat::Valv)
}

pub fn get_suffix_for_path_and_format(path: &Path, format: VaultFormat) -> &'static str {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default();

    match format {
        VaultFormat::Valv => match ext.as_str() {
            "jpg" | "jpeg" | "png" | "webp" | "bmp" | "svg" | "heic" | "heif" | "avif" | "ico" => {
                "-i.valv"
            }
            "gif" => "-g.valv",
            "mp4" | "mkv" | "mov" | "avi" | "webm" | "flv" | "3gp" | "wmv" | "m4v" => "-v.valv",
            "txt" | "pdf" | "doc" | "docx" | "md" | "json" | "csv" | "zip" | "tar" | "gz"
            | "7z" | "iso" => "-x.valv",
            _ => "-i.valv",
        },
        VaultFormat::Age => match ext.as_str() {
            "jpg" | "jpeg" | "png" | "webp" | "bmp" | "svg" | "heic" | "heif" | "avif" | "ico" => {
                "-i.age"
            }
            "gif" => "-g.age",
            "mp4" | "mkv" | "mov" | "avi" | "webm" | "flv" | "3gp" | "wmv" | "m4v" => "-v.age",
            "txt" | "pdf" | "doc" | "docx" | "md" | "json" | "csv" | "zip" | "tar" | "gz"
            | "7z" | "iso" => "-x.age",
            _ => "-i.age",
        },
    }
}

pub fn generate_random_filename(suffix: &str) -> String {
    let mut rng = rand::rng();
    let chars: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let random_str: String = (0..16)
        .map(|_| {
            let idx = rng.random_range(0..chars.len());
            chars[idx] as char
        })
        .collect();
    format!("{}{}", random_str, suffix)
}

pub fn is_valv_file(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    name.ends_with(".valv") || name.ends_with(".age")
}

pub fn sanitize_filename(name: &str) -> &str {
    let trimmed = name.trim();
    let basename = trimmed.rsplit(['/', '\\']).next().unwrap_or("");
    if basename.is_empty() || basename == "." || basename == ".." || basename.contains('\0') {
        "decrypted_file"
    } else {
        basename
    }
}

pub fn is_thumbnail_valv_file(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    name.ends_with("-t.valv") || name.ends_with("-t.age")
}

pub fn get_thumbnail_valv_name(valv_name: &str) -> Option<String> {
    if let Some(prefix) = valv_name
        .strip_suffix("-i.valv")
        .or_else(|| valv_name.strip_suffix("-g.valv"))
        .or_else(|| valv_name.strip_suffix("-v.valv"))
    {
        return Some(format!("{}-t.valv", prefix));
    }
    if let Some(prefix) = valv_name
        .strip_suffix("-i.age")
        .or_else(|| valv_name.strip_suffix("-g.age"))
        .or_else(|| valv_name.strip_suffix("-v.age"))
    {
        return Some(format!("{}-t.age", prefix));
    }
    None
}

pub fn collect_vault_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_vault_files_recursive(dir, &mut files);
    files
}

pub fn collect_vault_files_recursive(dir: &Path, files: &mut Vec<PathBuf>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.starts_with('.') || crate::config::is_manifest_file(&path) {
                continue;
            }
            if path.is_dir() {
                collect_vault_files_recursive(&path, files);
            } else if path.is_file() && is_valv_file(&path) && !is_thumbnail_valv_file(&path) {
                files.push(path);
            }
        }
    }
}

pub fn collect_plain_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_plain_files_recursive(dir, &mut files);
    files
}

pub fn collect_plain_files_recursive(dir: &Path, files: &mut Vec<PathBuf>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.starts_with('.') || crate::config::is_manifest_file(&path) {
                continue;
            }
            if path.is_dir() {
                collect_plain_files_recursive(&path, files);
            } else if path.is_file() {
                files.push(path);
            }
        }
    }
}

pub fn clean_empty_dirs_up_to(base: &Path, mut dir: &Path) {
    while dir != base && dir.starts_with(base) {
        if let Ok(mut entries) = fs::read_dir(dir) {
            if entries.next().is_none() {
                let _ = fs::remove_dir(dir);
            } else {
                break;
            }
        } else {
            break;
        }
        if let Some(parent) = dir.parent() {
            dir = parent;
        } else {
            break;
        }
    }
}
