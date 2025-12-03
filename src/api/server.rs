use crate::controllers::user_controller::{login, register_user};
use axum::Router;
use axum::routing::{get, post};
use tower_http::cors::{Any, CorsLayer};
use std::net::SocketAddr;
use azure_storage::StorageCredentialsInner::Anonymous;
use tokio::net::TcpListener;

// TODO: Implement the API module
// TODO: Add swagger documentation
// TODO: Rework API implementation use https://github.com/sheroz/axum-rest-api-sample as reference
pub async fn start() {
    let cors_layer = CorsLayer::new().allow_origin(Any);
    let router = Router::new()
        .route("/api", get(|| async { "Arrow Server API is running!" }))
        .route("/api/v1/users/register", post(register_user))
        .route("/api/v1/users/login", post(login))
        .with_state::<()>(());

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 3000)))
        .await
        .expect("Failed to bind to address");

    println!("Server running on http://127.0.0.1:3000");

    axum::serve(listener, router)
        .await
        .expect("Failed to start the server");
}
