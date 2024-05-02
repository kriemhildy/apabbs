// sec   min   hour   day of month   month   day of week   year
// *     *     *      *              *       *             *

use crate::{ban, init_db, BEGIN, COMMIT};
use tokio_cron_scheduler::Job;

pub fn scrub_ips() -> Job {
    Job::new_async("0 0 * * * * *", |_uuid, _l| {
        Box::pin(async move {
            let db = init_db().await;
            let mut tx = db.begin().await.expect(BEGIN);
            ban::scrub(&mut tx).await;
            tx.commit().await.expect(COMMIT);
            println!("old IP hashes scrubbed");
        })
    })
    .expect("make new job")
}
