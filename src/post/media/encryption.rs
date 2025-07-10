//! Media encryption and decryption helpers for posts.
//!
//! Provides GPG-based encryption and decryption utilities for post media files.

use super::super::{Post, submission::PostSubmission};
use std::{error::Error, path::Path};

/// Encrypts the provided bytes using GPG with the application's key.
pub async fn gpg_encrypt(
    encrypted_file_path: &Path,
    bytes: Vec<u8>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let encrypted_file_path_str = encrypted_file_path.to_str().unwrap();
    let mut child = tokio::process::Command::new("gpg")
        .args([
            "--batch",
            "--symmetric",
            "--passphrase-file",
            "gpg.key",
            "--output",
        ])
        .arg(encrypted_file_path_str)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn gpg process: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        tokio::io::AsyncWriteExt::write_all(&mut stdin, &bytes)
            .await
            .map_err(|e| format!("write to gpg stdin: {e}"))?;
    }
    let output = child
        .wait_with_output()
        .await
        .map_err(|e| format!("wait for gpg process: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "gpg failed with status: {}. stderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    if !encrypted_file_path.exists() {
        return Err("encrypted file does not exist".into());
    }
    tracing::info!("File encrypted successfully: {encrypted_file_path_str}",);
    Ok(())
}

/// Decrypts the post's media file using GPG.
pub async fn gpg_decrypt(
    encrypted_file_path: &Path,
) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    let encrypted_file_path_str = encrypted_file_path.to_str().unwrap();
    let output = tokio::process::Command::new("gpg")
        .args(["--batch", "--decrypt", "--passphrase-file", "gpg.key"])
        .arg(encrypted_file_path_str)
        .output()
        .await
        .map_err(|e| format!("execute gpg: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "gpg failed with status: {}. stderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    tracing::info!("File decrypted successfully: {encrypted_file_path_str}");
    Ok(output.stdout)
}


impl PostSubmission {
    /// Encrypts the uploaded file data for a post.
    pub async fn encrypt_uploaded_file(
        self,
        post: &Post,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let encrypted_file_path = post.encrypted_media_path();
        let uploads_key_dir = encrypted_file_path.parent().unwrap();
        tokio::fs::create_dir(uploads_key_dir).await?;
        let result = gpg_encrypt(&encrypted_file_path, self.media_bytes.unwrap()).await;
        if result.is_err() {
            tokio::fs::remove_dir(uploads_key_dir).await?;
        }
        result
    }
}
