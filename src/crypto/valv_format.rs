use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::path::Path;

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use pbkdf2::pbkdf2_hmac;
use rand::RngExt;
use sha2::Sha512;
use subtle::ConstantTimeEq;

use super::types::{
    BUFFER_SIZE, CHECK_LEN, DecryptError, DecryptedHeader, IV_LEN, MAX_ITERATIONS, MIN_ITERATIONS,
    SALT_LEN, VALV_V2, zeroize,
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

    let mut prefix_bytes = Vec::new();
    super::types::write_metadata_prefix(&mut prefix_bytes, original_name)?;
    cipher.apply_keystream(&mut prefix_bytes);
    writer.write_all(&prefix_bytes)?;

    transform_stream(&mut cipher, reader, writer)
}

pub struct ValvStreamReader<R> {
    pub cipher: ChaCha20,
    pub reader: R,
}

impl<R: Read> Read for ValvStreamReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.reader.read(buf)?;
        if n > 0 {
            self.cipher.apply_keystream(&mut buf[..n]);
        }
        Ok(n)
    }
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

    let valv_reader = ValvStreamReader { cipher, reader };
    let (original_name, payload) = super::types::extract_metadata_from_stream(valv_reader);

    Ok(DecryptedHeader {
        original_name,
        payload,
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
