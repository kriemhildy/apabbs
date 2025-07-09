//! Media encryption and decryption helpers for posts.
//!
//! Provides GPG-based encryption, decryption, and re-encryption utilities for post media files.
//!
//! Functions provided in this module:
//! - Post::gpg_encrypt
//! - Post::reencrypt_media_file
//! - Post::decrypt_media_file
//! - PostSubmission::encrypt_uploaded_file

use super::super::{Post, review::PostReview, submission::PostSubmission};
use std::error::Error;

impl Post {
    /// Encrypts the provided bytes using GPG with the application's key.
    pub async fn gpg_encrypt(&self, bytes: Vec<u8>) -> Result<(), Box<dyn Error + Send + Sync>> {
        let encrypted_file_path = self.encrypted_media_path();
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
    pub async fn gpg_decrypt(&self) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        let encrypted_file_path = self.encrypted_media_path();
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

    /// Re-encrypts a media file that has already been published.
    ///
    /// Used when media needs to be moved back from published to reported state.
    pub async fn reencrypt_media_file(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let encrypted_file_path = self.encrypted_media_path();
        let uploads_key_dir = encrypted_file_path.parent().unwrap();
        tokio::fs::create_dir(uploads_key_dir).await?;
        let media_file_path = self.published_media_path();
        let media_bytes = tokio::fs::read(&media_file_path).await?;
        let result = self.gpg_encrypt(media_bytes).await;
        match result {
            Ok(()) => PostReview::delete_media_key_dir(&self.key).await?,
            Err(_) => tokio::fs::remove_dir(uploads_key_dir).await?,
        }
        result.map_err(|e| format!("re-encrypt media: {e}").into())
    }
}

impl PostSubmission {
    /// Encrypts the uploaded file data for a post.
    pub async fn encrypt_uploaded_file(
        self,
        post: &Post,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let encrypted_file_path = post.encrypted_media_path();
        let uploads_key_dir = encrypted_file_path.parent().unwrap();
        tokio::fs::create_dir(uploads_key_dir).await.unwrap();
        let result = post.gpg_encrypt(self.media_bytes.unwrap()).await;
        if result.is_err() {
            tokio::fs::remove_dir(uploads_key_dir).await?;
        }
        result.map_err(|e| format!("encrypt uploaded file: {e}").into())
    }
}
