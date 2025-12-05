use axum::routing::{get, post, put, delete};
use axum::Router;
use crate::api::controllers::product_controller;

pub fn routes() -> Router {
    Router::new()
        .route("/", get(product_controller::get_all_products))
        .route("/", post(product_controller::create_product))
        .route("/{id}", get(product_controller::get_product_by_id))
        .route("/{id}", put(product_controller::update_product))
        .route("/{id}", delete(product_controller::delete_product))
}