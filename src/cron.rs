//! Scheduled job management for recurring system tasks.
//!
//! This module provides functionality for setting up and managing scheduled
//! background tasks that run at specific intervals. It handles maintenance
//! operations like database cleanup, privacy protection, and content
//! management tasks.
//!
//! # Key Functions
//!
//! - [`init`]: Sets up and starts the job scheduler system
//! - [`scrub_ips`]: Creates a job to remove old IP data for privacy
//!
//! # Cron Schedule Format
//!
//! The module uses the standard cron format for scheduling jobs:
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

use apabbs::{BEGIN, COMMIT, ban};
use tokio_cron_scheduler::Job;

/// Initializes and starts the scheduled job system
///
/// This function creates a new job scheduler, adds all scheduled jobs
/// to it (e.g., IP scrubbing), and starts the scheduler running.
/// The scheduler runs in the background for the lifetime of the application.
///
/// # Panics
/// Will panic if the scheduler cannot be created or started, which would
/// indicate a serious system issue.
pub async fn init() {
    use tokio_cron_scheduler::JobScheduler;
    let sched = JobScheduler::new().await.expect("make new job scheduler");

    // Add all scheduled jobs to the scheduler
    for job in [scrub_ips(), generate_screenshot()] {
        sched.add(job).await.expect("add job to scheduler");
    }

    // Start the scheduler running
    sched.start().await.expect("start scheduler");
}

/// Creates a scheduled job that removes old IP hash data for privacy
///
/// This job runs at 11:00 AM every day and removes IP address hashes
/// from posts and accounts that are older than the retention period.
/// This helps protect user privacy by not storing identifying information
/// longer than necessary.
///
/// # Schedule
/// Runs daily at 11:00 AM (0 0 11 * * *)
///
/// # Returns
/// A configured Job that can be added to the scheduler
fn scrub_ips() -> Job {
    Job::new_async("0 0 11 * * *", |_uuid, _l| {
        Box::pin(async move {
            // Connect to the database and start a transaction
            let db = apabbs::db().await;
            let mut tx = db.begin().await.expect(BEGIN);

            // Execute the IP scrubbing operation
            ban::scrub(&mut tx).await;

            // Commit the transaction
            tx.commit().await.expect(COMMIT);

            println!("old IP hashes scrubbed");
        })
    })
    .expect("make scrub job")
}

/// Creates a scheduled job that takes a screenshot of the application
///
/// This job runs hourly and captures a screenshot of the front page of the site,
/// saving it as a webp image in the public directory. The screenshot can be used
/// for previews, monitoring the application's appearance, or generating social
/// media cards.
///
/// The function uses Chromium in headless mode to render the page and capture the
/// screenshot. This potentially blocking operation is executed in a separate thread
/// using `tokio::task::spawn_blocking` to avoid blocking the async runtime.
///
/// # Schedule
/// Runs hourly at XX:55:00 (0 55 * * * *)
///
/// # Output
/// Saves the screenshot to `pub/screenshot.webp`
///
/// # Returns
/// A configured Job that can be added to the scheduler
fn generate_screenshot() -> Job {
    Job::new_async("0 55 * * * *", |_uuid, _l| {
        Box::pin(async move {
            use std::path::Path;
            use std::process::Command;

            // Determine the URL to screenshot
            let url = if apabbs::dev() {
                String::from("http://localhost")
            } else {
                format!("https://{}", apabbs::host())
            };

            // Ensure the output directory exists
            let output_path = Path::new("pub/screenshot.webp");
            if let Some(parent) = output_path.parent() {
                std::fs::create_dir_all(parent).expect("create output directory");
            }

            // Build the full output path
            let output_path_str = output_path
                .to_str()
                .expect("convert path to string")
                .to_owned();
            // Clone to move into the blocking task
            let url_clone = url.clone();

            // Run the blocking operation in a separate thread
            let status = tokio::task::spawn_blocking(move || {
                println!("Taking screenshot using chromium");

                // Execute Chromium with headless mode and other options
                Command::new("chromium")
                    .args([
                        "--headless=new",                             // New headless mode
                        "--hide-scrollbars",                          // Hide scrollbars
                        "--force-dark-mode",                          // Force dark mode
                        &format!("--screenshot={}", output_path_str), // Output file
                        &url_clone,                                   // URL to capture
                    ])
                    .status()
                    .expect("execute Chromium command")
            })
            .await
            .expect("screenshot task completed");

            if !status.success() {
                eprintln!(
                    "Failed to generate screenshot. Exit code: {:?}",
                    status.code()
                );
            }
        })
    })
    .expect("make screenshot job")
}
