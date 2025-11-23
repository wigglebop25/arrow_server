use std::net::SocketAddr;
use axum::Router;
use axum::routing::{get, post};
use tokio::net::TcpListener;
use crate::controllers::user_controller::{login, register_user};

// TODO: Implement the API module
pub async fn start() {
    let router = Router::new()
        .route("/" , get(|| async { "Arrow Server API is running!" }))
        .route("/users/register", post(register_user))
        .route("/users/login", post(login))
        .with_state::<()>(());

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 3000)))
        .await
        .expect("Failed to bind to address");

    println!("Server running on http://127.0.0.1:3000");

    axum::serve(listener, router)
        .await
        .expect("Failed to start the server");
}
