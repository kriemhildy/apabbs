// ┌──────────────── second (0 - 59)
// │ ┌────────────── minute (0 - 59)
// │ │ ┌──────────── hour (0 - 23)
// │ │ │ ┌────────── day of month (1 - 31)
// │ │ │ │ ┌──────── month (1 - 12, JAN-DEC)
// │ │ │ │ │ ┌────── day of week (0 - 6, SUN-Mon)
// │ │ │ │ │ │       (0 to 6 are Sunday to Saturday; 7 is Sunday, the same as 0)
// │ │ │ │ │ │
// * * * * * *

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
    let job = scrub_ips();
    sched.add(job).await.expect("add job to scheduler");

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
            let db = crate::db().await;
            let mut tx = db.begin().await.expect(BEGIN);

            // Execute the IP scrubbing operation
            ban::scrub(&mut tx).await;

            // Commit the transaction
            tx.commit().await.expect(COMMIT);

            println!("old IP hashes scrubbed");
        })
    })
    .expect("make new job")
}
