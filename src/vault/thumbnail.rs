use std::fs::File;
use std::io::{BufWriter, Cursor};
use std::path::Path;
use std::process::Command;

use crate::crypto::{encrypt_stream_unified, EncryptionMethod, BUFFER_SIZE};

// simplification: calls ffmpeg (primary) or imagemagick (fallback) to generate a 512x512
// center-cropped JPEG thumbnail. Ceiling: requires system ffmpeg or convert; upgrade path:
// embed pure Rust decoders if external tools cannot be assumed.
pub fn generate_thumbnail(path: &Path) -> Option<Vec<u8>> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default();

    let is_media = matches!(
        ext.as_str(),
        "jpg"
            | "jpeg"
            | "png"
            | "webp"
            | "bmp"
            | "gif"
            | "svg"
            | "heic"
            | "heif"
            | "avif"
            | "ico"
            | "mp4"
            | "mkv"
            | "mov"
            | "avi"
            | "webm"
            | "flv"
            | "3gp"
            | "wmv"
            | "m4v"
    );
    if !is_media {
        return None;
    }

    if let Ok(out) = Command::new("ffmpeg")
        .args([
            "-y",
            "-loglevel",
            "error",
            "-protocol_whitelist",
            "file",
            "-ss",
            "00:00:00",
            "-i",
        ])
        .arg(path)
        .args([
            "-frames:v",
            "1",
            "-filter:v",
            "scale=512:512:force_original_aspect_ratio=increase,crop=512:512",
            "-f",
            "image2",
            "-c:v",
            "mjpeg",
            "-q:v",
            "3",
            "pipe:1",
        ])
        .output()
        && out.status.success()
        && out.stdout.len() > 100
    {
        return Some(out.stdout);
    }

    if let Ok(out) = Command::new("convert")
        .arg(path)
        .args([
            "-resize",
            "512x512^",
            "-gravity",
            "center",
            "-extent",
            "512x512",
            "-quality",
            "85",
            "jpeg:-",
        ])
        .output()
        && out.status.success()
        && out.stdout.len() > 100
    {
        return Some(out.stdout);
    }

    None
}

pub fn create_thumbnail_file_unified(
    source_path: &Path,
    dest_path: &Path,
    orig_filename: &str,
    method: &EncryptionMethod,
) -> std::io::Result<bool> {
    if let Some(thumb_data) = generate_thumbnail(source_path) {
        let out_file = File::create(dest_path)?;
        let mut out_writer = BufWriter::with_capacity(BUFFER_SIZE, out_file);
        encrypt_stream_unified(
            &mut Cursor::new(thumb_data),
            &mut out_writer,
            orig_filename,
            method,
        )?;
        Ok(true)
    } else {
        Ok(false)
    }
}
