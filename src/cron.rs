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
    let sched = JobScheduler::new().await.expect("creates job scheduler");

    // Add all scheduled jobs to the scheduler
    for job in [scrub_ips(), generate_screenshot()] {
        sched.add(job).await.expect("adds job to scheduler");
    }

    // Start the scheduler running
    sched.start().await.expect("starts job scheduler");
}

/// Creates a scheduled job that removes old IP hash data for privacy.
pub fn scrub_ips() -> Job {
    Job::new_async("0 0 11 * * *", |_uuid, _l| {
        Box::pin(async move {
            tracing::info!("Scrubbing old IP hashes");

            // Connect to the database and start a transaction
            let db = crate::init_db().await;
            let mut tx = db.begin().await.expect("begins transaction");

            // Execute the IP scrubbing operation
            ban::scrub(&mut tx).await.expect("query succeeds");

            // Commit the transaction
            tx.commit().await.expect("commits transaction");

            tracing::info!("Old IP hashes scrubbed");
        })
    })
    .expect("creates ip scrub job")
}

/// Creates a scheduled job that takes a screenshot of the application and saves it to disk.
pub fn generate_screenshot() -> Job {
    Job::new_async("0 55 * * * *", |_uuid, _l| {
        Box::pin(async move {
            use std::path::Path;

            tracing::info!("Taking screenshot with Chromium");

            // Determine the URL to screenshot
            let url = if crate::dev() {
                String::from("http://localhost")
            } else {
                format!("https://{}", crate::host())
            };

            // Ensure the output directory exists
            let output_path = Path::new("pub/screenshot.webp");

            // Build the full output path
            let output_path_str = output_path
                .to_str()
                .expect("converts path to string")
                .to_string();
            let url_clone = url.clone();
            let output_path_str_clone = output_path_str.clone();

            // Run the Chromium command to take a screenshot
            let status = tokio::process::Command::new("chromium")
                .args([
                    "--headless",
                    "--hide-scrollbars",
                    "--force-dark-mode",
                    "--window-size=1920,1080",
                    &format!("--screenshot={output_path_str_clone}"),
                    &url_clone,
                ])
                .stderr(std::process::Stdio::null())
                .status()
                .await
                .expect("executes chromium command");

            if status.success() {
                tracing::info!(
                    output_path = ?output_path,
                    "Chromium screenshot saved"
                );
            } else {
                tracing::error!(
                    "Failed to generate screenshot. Chromium exited with code: {:?}",
                    status.code()
                );
            }
        })
    })
    .expect("creates screenshot job")
}
