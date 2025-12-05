use axum::routing::{get, post};
use axum::Router;
use crate::api::controllers::order_controller;

pub fn routes() -> Router {
    Router::new()
        .route("/", get(order_controller::get_all_orders))
        .route("/", post(order_controller::create_order))
        .route("/{id}", get(order_controller::get_order_by_id))
        .route("/user/{username}", get(order_controller::get_user_orders_by_name))
}