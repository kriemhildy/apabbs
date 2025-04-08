#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    let _db = apabbs::db().await;
    println!("migrating");
}
