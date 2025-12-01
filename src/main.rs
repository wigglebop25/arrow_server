#[tokio::main]
async fn main() {
    arrow_server_lib::api::server::start().await;
}
