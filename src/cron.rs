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
use std::error::Error;
use tokio_cron_scheduler::Job;

/// The path where screenshots will be saved
#[cfg(test)]
const SCREENSHOT_PATH: &str = "pub/test_screenshot.webp";
#[cfg(not(test))]
const SCREENSHOT_PATH: &str = "pub/screenshot.webp";

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

/// The function executed by the scrub job.
pub async fn scrub_task() {
    let result: Result<(), Box<dyn Error + Send + Sync>> = async {
        tracing::info!("Scrubbing old IP hashes...");

        // Connect to the database and start a transaction
        let db = crate::init_db().await;
        let mut tx = db.begin().await?;

        // Execute the IP scrubbing operation
        ban::scrub(&mut tx).await?;

        // Commit the transaction
        tx.commit().await?;
        Ok(())
    }
    .await;

    match result {
        Err(e) => tracing::error!("Failed to scrub old IP hashes: {e}"),
        Ok(_) => tracing::info!("Scrub task completed successfully"),
    }
}

/// Creates a scheduled job that removes old IP hash data for privacy.
pub fn create_scrub_job() -> Job {
    Job::new_async("0 0 11 * * *", |_uuid, _l| Box::pin(scrub_task())).expect("Create job")
}

/// Takes a screenshot of the homepage.
pub async fn screenshot_task() {
    let result: Result<(), Box<dyn Error + Send + Sync>> = async {
        let url = if crate::dev() {
            "http://localhost".to_string()
        } else {
            format!("https://{}", crate::host())
        };
        tracing::info!(url, SCREENSHOT_PATH, "Taking screenshot with Chromium...");
        let status = tokio::process::Command::new("chromium")
            .args([
                "--headless",
                "--hide-scrollbars",
                "--force-dark-mode",
                "--window-size=1920,1080",
                &format!("--screenshot={SCREENSHOT_PATH}"),
                &url,
            ])
            .stderr(std::process::Stdio::null())
            .status()
            .await
            .map_err(|e| format!("Failed to execute chromium: {e}"))?;

        if status.success() {
            Ok(())
        } else {
            Err(format!("Chromium exited with code: {:?}", status.code()).into())
        }
    }
    .await;

    match result {
        Err(e) => tracing::error!(SCREENSHOT_PATH, "Failed to take screenshot: {e}"),
        Ok(_) => tracing::info!(SCREENSHOT_PATH, "Chromium screenshot saved"),
    }
}

/// Creates a scheduled job that takes a screenshot of the application and saves it to disk.
pub fn create_screenshot_job() -> Job {
    Job::new_async("0 55 * * * *", |_uuid, _l| Box::pin(screenshot_task())).expect("Create job")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[tokio::test]
    async fn test_screenshot_task() {
        assert!(
            fs::metadata(SCREENSHOT_PATH).is_err(),
            "Screenshot file should not exist before test"
        );
        screenshot_task().await;
        assert!(
            fs::metadata(SCREENSHOT_PATH).is_ok(),
            "Screenshot file should exist"
        );
        // Clean up
        fs::remove_file(SCREENSHOT_PATH).expect("Remove test screenshot");
    }

    #[tokio::test]
    async fn test_init() {
        init().await;
    }
}
