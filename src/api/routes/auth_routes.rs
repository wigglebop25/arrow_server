use crate::api::controllers::user_controller::{login, register_user};
use axum::Router;
use axum::routing::post;

pub fn routes() -> Router<()> {
    Router::new()
        .route("/login", post(login))
        .route("/register", post(register_user))
}
