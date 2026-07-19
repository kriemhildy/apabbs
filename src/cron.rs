//! Background job scheduling and automated maintenance tasks.
//!
//! This module sets up and manages recurring background jobs using cron-like schedules.
//! Handles automated maintenance such as database cleanup (scrubbing old IP hashes for privacy)
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
pub const SCREENSHOT_PATH: &str = "pub/screenshot.webp";

/// Initializes and starts the scheduled job system in the background for the app's lifetime.
pub async fn init() {
    use tokio_cron_scheduler::JobScheduler;
    let sched = JobScheduler::new().await.expect("create job scheduler");

    // Add all scheduled jobs to the scheduler
    for job in [create_scrub_job(), create_screenshot_job()] {
        sched.add(job).await.expect("add job to scheduler");
    }

    // Start the scheduler running
    sched.start().await.expect("start job scheduler");
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
        Err(e) => {
            let msg = format!("Failed to scrub old IP hashes: {e}");
            tracing::error!("{msg}");
            #[cfg(feature = "sentry")]
            sentry::capture_message(&msg, sentry::Level::Error);
        }
        Ok(_) => tracing::info!("Scrub task completed successfully"),
    }
}

/// Creates a scheduled job that removes old IP hash data for privacy.
pub fn create_scrub_job() -> Job {
    Job::new_async("0 0 11 * * *", |_uuid, _l| Box::pin(scrub_task())).expect("Create job")
}

/// Takes a screenshot of the homepage.
pub async fn screenshot_task(screenshot_path_str: &str) {
    let result: Result<(), Box<dyn Error + Send + Sync>> = async {
        let url = if crate::dev() {
            "http://localhost".to_string()
        } else {
            format!("https://{}", crate::prod_host())
        };

        tracing::info!(url, screenshot_path_str, "Taking screenshot with Chrome...");

        let chrome_status = tokio::process::Command::new("npm")
            .args([
                "run",
                "chrome",
                "--",
                "--headless",
                "--window-size=1400,800",
                &format!("--screenshot={screenshot_path_str}"),
                &url,
            ])
            .stderr(std::process::Stdio::null())
            .status()
            .await
            .map_err(|e| format!("execute Chrome: {e}"))?;

        if !chrome_status.success() {
            return Err(format!("Chrome exited with code: {:?}", chrome_status.code()).into());
        }

        Ok(())
    }
    .await;

    match result {
        Err(e) => {
            let msg = format!("Failed to take screenshot: {e}");
            tracing::error!(screenshot_path_str, "{msg}");
            #[cfg(feature = "sentry")]
            sentry::with_scope(
                |scope| {
                    scope.set_extra("screenshot_path_str", screenshot_path_str.into());
                },
                || {
                    sentry::capture_message(&msg, sentry::Level::Error);
                },
            );
        }
        Ok(_) => tracing::info!(screenshot_path_str, "Chrome screenshot saved"),
    }
}

/// Creates a scheduled job that takes a screenshot of the application and saves it to disk.
pub fn create_screenshot_job() -> Job {
    Job::new_async("0 55 * * * *", |_uuid, _l| {
        Box::pin(screenshot_task(SCREENSHOT_PATH))
    })
    .expect("Create job")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_init() {
        init().await;
    }
}
