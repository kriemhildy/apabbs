//! Background job scheduling and automated maintenance tasks.
//!
//! This module sets up and manages recurring background jobs using cron-like schedules.
//! It handles automated maintenance such as database cleanup (e.g., scrubbing old IP hashes for privacy)
//! and periodic content management (e.g., generating application screenshots for status pages).
//!
//! # Scheduling Format
//! Uses standard cron syntax for job timing:
//!
//! ```text
//! ┌──────────────── second (0 - 59)
//! │ ┌────────────── minute (0 - 59)
//! │ │ ┌──────────── hour (0 - 23)
//! │ │ │ ┌────────── day of month (1 - 31)
//! │ │ │ │ ┌──────── month (1 - 12, JAN-DEC)
//! │ │ │ │ │ ┌────── day of week (0 - 6, SUN-MON)
//! │ │ │ │ │ │       (0 to 6 are Sunday to Saturday; 7 is Sunday, the same as 0)
//! │ │ │ │ │ │
//! * * * * * *
//! ```

use crate::ban;
use tokio_cron_scheduler::Job;

/// Initializes and starts the scheduled job system in the background for the application's lifetime.
pub async fn init() {
    use tokio_cron_scheduler::JobScheduler;
    let sched = JobScheduler::new().await.expect("Create job scheduler");

    // Add all scheduled jobs to the scheduler
    for job in [create_scrub_job(), create_screenshot_job()] {
        sched.add(job).await.expect("Add job to scheduler");
    }

    // Start the scheduler running
    sched.start().await.expect("Start job scheduler");
}

/// Creates a scheduled job that removes old IP hash data for privacy.
pub fn create_scrub_job() -> Job {
    Job::new_async("0 0 11 * * *", |_uuid, _l| {
        Box::pin(async move {
            tracing::info!("Scrubbing old IP hashes");

            // Connect to the database and start a transaction
            let db = crate::init_db().await;
            let mut tx = db.begin().await.expect("Begin transaction");

            // Execute the IP scrubbing operation
            ban::scrub(&mut tx).await.expect("Execute query");

            // Commit the transaction
            tx.commit().await.expect("Commit transaction");

            tracing::info!("Old IP hashes scrubbed");
        })
    })
    .expect("Create job")
}

/// Takes a screenshot of the given URL and saves it to the specified output path.
pub async fn take_screenshot(url: &str, output_path: &str) -> Result<(), String> {
    tracing::info!(url, output_path, "Taking screenshot with Chromium...");
    let status = tokio::process::Command::new("chromium")
        .args([
            "--headless",
            "--hide-scrollbars",
            "--force-dark-mode",
            "--window-size=1920,1080",
            &format!("--screenshot={output_path}"),
            url,
        ])
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .map_err(|e| format!("Failed to execute chromium: {e}"))?;

    if status.success() {
        tracing::info!(output_path, "Chromium screenshot saved");
        Ok(())
    } else {
        let msg = format!(
            "Failed to generate screenshot. Chromium exited with code: {:?}",
            status.code()
        );
        tracing::error!("{msg}");
        Err(msg)
    }
}

/// Creates a scheduled job that takes a screenshot of the application and saves it to disk.
pub fn create_screenshot_job() -> Job {
    Job::new_async("0 55 * * * *", |_uuid, _l| {
        Box::pin(async move {
            let url = if crate::dev() {
                "http://localhost".to_string()
            } else {
                format!("https://{}", crate::host())
            };
            let output_path = "pub/screenshot.webp";
            if let Err(e) = take_screenshot(&url, output_path).await {
                tracing::error!("Scheduled screenshot failed: {e}");
            }
        })
    })
    .expect("Create job")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[tokio::test]
    async fn take_screenshot_creates_file() {
        let url = "https://example.com";
        let output_path = "pub/test_screenshot.webp";
        let result = take_screenshot(url, output_path).await;
        assert!(result.is_ok(), "Screenshot should succeed: {result:?}");
        assert!(
            fs::metadata(output_path).is_ok(),
            "Screenshot file should exist"
        );
        // Clean up
        fs::remove_file(output_path).expect("Remove test screenshot");
    }
}
