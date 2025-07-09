use super::super::{Post, review::PostReview, submission::PostSubmission};
use std::error::Error;

impl Post {
    /// Encrypts the provided bytes using GPG with the application's key.
    pub async fn gpg_encrypt(&self, bytes: Vec<u8>) -> Result<(), Box<dyn Error + Send + Sync>> {
        let encrypted_media_path = self.encrypted_media_path();
        let encrypted_media_path_str = encrypted_media_path
            .to_str()
            .ok_or("failed to convert encrypted media path to string")?
            .to_string();
        let mut child = tokio::process::Command::new("gpg")
            .args([
                "--batch",
                "--symmetric",
                "--passphrase-file",
                "gpg.key",
                "--output",
            ])
            .arg(&encrypted_media_path_str)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("failed to spawn gpg process: {e}"))?;
        if let Some(mut stdin) = child.stdin.take() {
            tokio::io::AsyncWriteExt::write_all(&mut stdin, &bytes)
                .await
                .map_err(|e| format!("failed to write to gpg stdin: {e}"))?;
        }
        let child_status = child
            .wait()
            .await
            .map_err(|e| format!("failed to wait for gpg process: {e}"))?;
        if !child_status.success() {
            return Err("gpg failed to encrypt file".into());
        }
        tracing::info!(
            "File encrypted successfully: {}",
            encrypted_media_path.display()
        );
        Ok(())
    }

    /// Re-encrypts a media file that has already been published.
    ///
    /// Used when media needs to be moved back from published to reported state.
    pub async fn reencrypt_media_file(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let encrypted_file_path = self.encrypted_media_path();
        let uploads_key_dir = encrypted_file_path
            .parent()
            .ok_or("encrypted file path has no parent directory")?;
        tokio::fs::create_dir(uploads_key_dir)
            .await
            .map_err(|e| format!("failed to create uploads key directory: {e}"))?;
        let media_file_path = self.published_media_path();
        let media_bytes = tokio::fs::read(&media_file_path)
            .await
            .map_err(|e| format!("failed to read published media file: {e}"))?;
        let result = self
            .gpg_encrypt(media_bytes)
            .await
            .map_err(|e| format!("failed to encrypt media during re-encryption: {e}"));
        match result {
            Ok(()) => PostReview::delete_media_key_dir(&self.key)
                .await
                .map_err(|e| {
                    format!("failed to delete media key directory after re-encryption: {e}")
                })?,
            Err(ref msg) => {
                tokio::fs::remove_dir(uploads_key_dir).await.map_err(|e| {
                    format!(
                        "failed to remove uploads key directory after failed re-encryption: {e}"
                    )
                })?;
                tracing::error!("Re-encryption failed: {msg}");
            }
        }
        result.map_err(|e| e.into())
    }

    /// Decrypts the post's media file using GPG.
    pub async fn decrypt_media_file(&self) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        if self.media_filename.is_none() {
            return Err("cannot decrypt media: post has no media file".into());
        }
        let encrypted_file_path = self
            .encrypted_media_path()
            .to_str()
            .ok_or("failed to convert encrypted media path to string")?
            .to_string();
        let output = tokio::process::Command::new("gpg")
            .args(["--batch", "--decrypt", "--passphrase-file", "gpg.key"])
            .arg(&encrypted_file_path)
            .output()
            .await
            .map_err(|e| format!("failed to execute GPG for decryption: {e}"))?;
        if !output.status.success() {
            return Err(format!("GPG failed to decrypt file, status: {}", output.status).into());
        }
        tracing::info!(
            key = self.key,
            media_filename = self.media_filename,
            "Media file decrypted successfully"
        );
        Ok(output.stdout)
    }
}

impl PostSubmission {
    /// Encrypts the uploaded file data for a post.
    pub async fn encrypt_uploaded_file(
        self,
        post: &Post,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        if self.media_bytes.is_none() {
            return Err("no media bytes provided for encryption".into());
        }
        let encrypted_file_path = post.encrypted_media_path();
        let uploads_key_dir = encrypted_file_path
            .parent()
            .ok_or("encrypted file path has no parent directory")?;
        tokio::fs::create_dir(uploads_key_dir)
            .await
            .map_err(|e| format!("failed to create uploads key directory: {e}"))?;
        let result = post.gpg_encrypt(self.media_bytes.unwrap()).await;
        if result.is_err() {
            tokio::fs::remove_dir(uploads_key_dir).await.map_err(|e| {
                format!("failed to remove uploads key directory after failed encryption: {e}")
            })?;
        }
        result
    }
}
