use std::fs::File;
use std::io::{self, BufReader, Cursor, Read, Write};
use std::path::Path;

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use pbkdf2::pbkdf2_hmac;
use rand::RngExt;
use sha2::Sha512;
use subtle::ConstantTimeEq;

use super::types::{
    zeroize, DecryptError, DecryptedHeader, DecryptedPayload, ValvMetadata, BUFFER_SIZE,
    CHECK_LEN, IV_LEN, MAX_ITERATIONS, MIN_ITERATIONS, SALT_LEN, VALV_V2,
};

pub fn derive_key(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha512>(password, salt, iterations, &mut key);
    key
}

pub fn transform_stream<R: Read, W: Write>(
    cipher: &mut ChaCha20,
    reader: &mut R,
    writer: &mut W,
) -> io::Result<()> {
    let mut buffer = vec![0u8; BUFFER_SIZE];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        cipher.apply_keystream(&mut buffer[..n]);
        writer.write_all(&buffer[..n])?;
    }
    writer.flush()?;
    Ok(())
}

pub fn encrypt_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    password: &[u8],
    original_name: &str,
    iterations: u32,
) -> io::Result<()> {
    if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Iterations must be between {} and {}",
                MIN_ITERATIONS, MAX_ITERATIONS
            ),
        ));
    }

    let mut rng = rand::rng();
    let mut salt = [0u8; SALT_LEN];
    let mut iv = [0u8; IV_LEN];
    let mut check_bytes = [0u8; CHECK_LEN];
    rng.fill(&mut salt);
    rng.fill(&mut iv);
    rng.fill(&mut check_bytes);

    writer.write_all(&VALV_V2.to_be_bytes())?;
    writer.write_all(&salt)?;
    writer.write_all(&iv)?;
    writer.write_all(&iterations.to_be_bytes())?;
    writer.write_all(&check_bytes)?;

    let mut key = derive_key(password, &salt, iterations);
    let mut cipher = ChaCha20::new(&key.into(), &iv.into());
    zeroize(&mut key);

    let mut encrypted_check = check_bytes;
    cipher.apply_keystream(&mut encrypted_check);
    writer.write_all(&encrypted_check)?;

    let meta = serde_json::to_string(&ValvMetadata {
        original_name: original_name.to_string(),
    })
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let mut prefix_bytes = Vec::with_capacity(meta.len() + 2);
    prefix_bytes.push(b'\n');
    prefix_bytes.extend_from_slice(meta.as_bytes());
    prefix_bytes.push(b'\n');

    cipher.apply_keystream(&mut prefix_bytes);
    writer.write_all(&prefix_bytes)?;

    transform_stream(&mut cipher, reader, writer)
}

pub fn decrypt_valv_v2_header<'a, R: Read + Send + 'a>(
    mut reader: R,
    password: &[u8],
) -> Result<DecryptedHeader<'a>, DecryptError> {
    let mut version_bytes = [0u8; 4];
    reader.read_exact(&mut version_bytes)?;
    let version = u32::from_be_bytes(version_bytes);
    if version != VALV_V2 {
        return Err(DecryptError::CorruptHeader("Unsupported version"));
    }

    let mut salt = [0u8; SALT_LEN];
    let mut iv = [0u8; IV_LEN];
    let mut iters_bytes = [0u8; 4];
    let mut check_bytes = [0u8; CHECK_LEN];
    let mut encrypted_check = [0u8; CHECK_LEN];

    reader.read_exact(&mut salt)?;
    reader.read_exact(&mut iv)?;
    reader.read_exact(&mut iters_bytes)?;
    reader.read_exact(&mut check_bytes)?;
    reader.read_exact(&mut encrypted_check)?;

    let iterations = u32::from_be_bytes(iters_bytes);
    if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations) {
        return Err(DecryptError::CorruptHeader("Invalid iterations"));
    }

    let mut key = derive_key(password, &salt, iterations);
    let mut cipher = ChaCha20::new(&key.into(), &iv.into());
    zeroize(&mut key);

    let mut decrypted_check = encrypted_check;
    cipher.apply_keystream(&mut decrypted_check);

    if check_bytes.ct_eq(&decrypted_check).unwrap_u8() != 1 {
        return Err(DecryptError::InvalidPassword);
    }

    let mut first_byte = [0u8; 1];
    reader.read_exact(&mut first_byte)?;
    cipher.apply_keystream(&mut first_byte);

    if first_byte[0] != b'\n' {
        let chained = Cursor::new(vec![first_byte[0]]).chain(reader);
        return Ok(DecryptedHeader {
            original_name: "decrypted_file".to_string(),
            payload: DecryptedPayload::Valv {
                cipher,
                reader: Box::new(chained),
            },
        });
    }

    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    let mut found_newline = false;

    while buf.len() < 4096 {
        reader.read_exact(&mut byte)?;
        cipher.apply_keystream(&mut byte);
        if byte[0] == b'\n' {
            found_newline = true;
            break;
        }
        buf.push(byte[0]);
    }

    if found_newline
        && let Ok(meta_str) = std::str::from_utf8(&buf)
        && let Ok(meta) = serde_json::from_str::<ValvMetadata>(meta_str)
    {
        return Ok(DecryptedHeader {
            original_name: meta.original_name,
            payload: DecryptedPayload::Valv {
                cipher,
                reader: Box::new(reader),
            },
        });
    }

    let mut full_buf = Vec::with_capacity(1 + buf.len() + 1);
    full_buf.push(b'\n');
    full_buf.extend_from_slice(&buf);
    if found_newline {
        full_buf.push(b'\n');
    }
    let chained = Cursor::new(full_buf).chain(reader);

    Ok(DecryptedHeader {
        original_name: "decrypted_file".to_string(),
        payload: DecryptedPayload::Valv {
            cipher,
            reader: Box::new(chained),
        },
    })
}

pub fn encrypt_file(
    source: &Path,
    dest: &Path,
    password: &[u8],
    original_name: &str,
    iterations: u32,
) -> io::Result<()> {
    let mut in_file = BufReader::with_capacity(BUFFER_SIZE, File::open(source)?);
    let out_file = File::create(dest)?;
    let mut out_writer = io::BufWriter::with_capacity(BUFFER_SIZE, out_file);
    encrypt_stream(
        &mut in_file,
        &mut out_writer,
        password,
        original_name,
        iterations,
    )
}
