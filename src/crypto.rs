use crate::error::{AppError, Result};
use crate::types::AppContext;
use rsa::RsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::pss::{Signature, VerifyingKey};
use rsa::sha2::{Digest, Sha256};
use rsa::signature::DigestVerifier;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::os::unix::io::AsRawFd;
use std::path::Path;

pub fn hash_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;

    unsafe {
        libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_SEQUENTIAL);
    }

    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 131_072];

    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }

    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect())
}

pub fn verify_sha256(file_path: &Path, expected_hash: &str) -> bool {
    match hash_file(file_path) {
        Ok(hash) => hash == expected_hash,
        Err(_) => false,
    }
}

fn is_key_revoked(public_key: &RsaPublicKey, ctx: &AppContext) -> bool {
    use rsa::pkcs8::EncodePublicKey;
    let revoked_path = ctx.root_path("etc/bhpkg/keys/revoked.txt");
    if !revoked_path.exists() {
        return false;
    }

    if let Ok(der_bytes) = public_key.to_public_key_der() {
        let mut hasher = Sha256::new();
        hasher.update(der_bytes.as_bytes());
        let hex_hash: String = hasher
            .finalize()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();

        if let Ok(file) = File::open(revoked_path) {
            let reader = BufReader::new(file);
            for line in reader.lines().map_while(std::result::Result::ok) {
                if line.trim() == hex_hash {
                    return true;
                }
            }
        }
    }
    false
}

pub fn verify_signature(
    file_path: &Path,
    sig_path: &Path,
    pubkey_path: &str,
    ctx: &AppContext,
) -> Result<bool> {
    let pubkey_str = std::fs::read_to_string(pubkey_path)
        .map_err(|_| AppError::Crypto(format!("Public key not found at {}", pubkey_path)))?;

    let public_key = RsaPublicKey::from_public_key_pem(&pubkey_str)
        .map_err(|_| AppError::Crypto("Failed to parse RSA public key".into()))?;

    if is_key_revoked(&public_key, ctx) {
        return Err(AppError::Security(
            "CRITICAL: The repository public key HAS BEEN REVOKED! Aborting.".into(),
        ));
    }

    let signature_bytes = std::fs::read(sig_path)?;

    let signature = Signature::try_from(signature_bytes.as_slice())
        .map_err(|_| AppError::Crypto("Invalid PSS signature format".into()))?;

    let verifying_key = VerifyingKey::<Sha256>::new(public_key);
    let mut file = File::open(file_path)?;

    unsafe {
        libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_SEQUENTIAL);
    }

    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 131_072];

    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }

    Ok(verifying_key.verify_digest(hasher, &signature).is_ok())
}
