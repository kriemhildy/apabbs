//! Background job scheduling and automated maintenance tasks.
//!
//! This module sets up and manages recurring background jobs using cron-like schedules.
//! It handles automated maintenance such as database cleanup (e.g., scrubbing old IP hashes for privacy)
//! and periodic content management (e.g., generating application screenshots for status pages).
//!
//! # Key Functions
//! - [`init`]: Initializes and starts the job scheduler system.
//! - [`scrub_ips`]: Schedules a daily job to remove old IP data for privacy protection.
//! - [`generate_screenshot`]: Schedules an hourly job to capture a screenshot of the application.
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

/// Initializes and starts the scheduled job system.
///
/// Creates a new job scheduler, adds all scheduled jobs to it (e.g., IP scrubbing, screenshot),
/// and starts the scheduler running in the background for the application's lifetime.
///
/// # Panics
/// Panics if the scheduler cannot be created or started.
pub async fn init() {
    use tokio_cron_scheduler::JobScheduler;
    let sched = JobScheduler::new()
        .await
        .expect("Failed to create job scheduler");

    // Add all scheduled jobs to the scheduler
    for job in [scrub_ips(), generate_screenshot()] {
        sched
            .add(job)
            .await
            .expect("Failed to add job to scheduler");
    }

    // Start the scheduler running
    sched.start().await.expect("Failed to start job scheduler");
}

/// Creates a scheduled job that removes old IP hash data for privacy.
///
/// Runs daily at 11:00 AM (0 0 11 * * *).
pub fn scrub_ips() -> Job {
    Job::new_async("0 0 11 * * *", |_uuid, _l| {
        Box::pin(async move {
            // Connect to the database and start a transaction
            let db = crate::db().await;
            let mut tx = db.begin().await.expect("begin should succeed");

            // Execute the IP scrubbing operation
            ban::scrub(&mut tx).await;

            // Commit the transaction
            tx.commit().await.expect("commit should succeed");

            println!("Old IP hashes scrubbed");
        })
    })
    .expect("Failed to create IP scrub job")
}

/// Creates a scheduled job that takes a screenshot of the application.
///
/// Runs hourly at XX:55:00 (0 55 * * * *).
/// Saves the screenshot to `pub/screenshot.webp`.
pub fn generate_screenshot() -> Job {
    Job::new_async("0 55 * * * *", |_uuid, _l| {
        Box::pin(async move {
            use std::path::Path;
            use std::process::Command;

            // Determine the URL to screenshot
            let url = if crate::dev() {
                String::from("http://localhost")
            } else {
                format!("https://{}", crate::host())
            };

            // Ensure the output directory exists
            let output_path = Path::new("pub/screenshot.webp");
            if let Some(parent) = output_path.parent() {
                std::fs::create_dir_all(parent)
                    .expect("Failed to create output directory for screenshot");
            }

            // Build the full output path
            let output_path_str = output_path
                .to_str()
                .expect("Failed to convert screenshot path to string")
                .to_owned();
            let url_clone = url.clone();
            let output_path_str_clone = output_path_str.clone();

            // Run the blocking operation in a separate thread
            let status = tokio::task::spawn_blocking(move || {
                println!("Taking screenshot using Chromium");
                Command::new("chromium")
                    .args([
                        "--headless=new",
                        "--disable-gpu",
                        "--hide-scrollbars",
                        "--force-dark-mode",
                        &format!("--screenshot={}", output_path_str_clone),
                        &url_clone,
                    ])
                    .stderr(std::process::Stdio::null())
                    .status()
                    .expect("Failed to execute Chromium command for screenshot")
            })
            .await
            .expect("Screenshot task did not complete");

            if status.success() {
                println!("Screenshot saved to {}", output_path_str);
            } else {
                eprintln!(
                    "Failed to generate screenshot. Chromium exited with code: {:?}",
                    status.code()
                );
            }
        })
    })
    .expect("Failed to create screenshot job")
}
