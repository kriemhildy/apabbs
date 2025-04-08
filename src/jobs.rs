// ┌──────────────── second (0 - 59)
// │ ┌────────────── minute (0 - 59)
// │ │ ┌──────────── hour (0 - 23)
// │ │ │ ┌────────── day of month (1 - 31)
// │ │ │ │ ┌──────── month (1 - 12, JAN-DEC)
// │ │ │ │ │ ┌────── day of week (0 - 6, SUN-Mon)
// │ │ │ │ │ │       (0 to 6 are Sunday to Saturday; 7 is Sunday, the same as 0)
// │ │ │ │ │ │
// * * * * * *

use crate::{BEGIN, COMMIT, ban};
use tokio_cron_scheduler::Job;

pub async fn init() {
    use tokio_cron_scheduler::JobScheduler;
    let sched = JobScheduler::new().await.expect("make new job scheduler");
    let job = scrub_ips();
    sched.add(job).await.expect("add job to scheduler");
    sched.start().await.expect("start scheduler");
}

pub fn scrub_ips() -> Job {
    Job::new_async("0 0 11 * * *", |_uuid, _l| {
        Box::pin(async move {
            let db = crate::db().await;
            let mut tx = db.begin().await.expect(BEGIN);
            ban::scrub(&mut tx).await;
            tx.commit().await.expect(COMMIT);
            println!("old IP hashes scrubbed");
        })
    })
    .expect("make new job")
}
