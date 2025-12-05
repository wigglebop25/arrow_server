use crate::api::controllers::role_controller::*;
use axum::Router;
use axum::routing::{delete, get, patch, post};

pub fn routes() -> Router<()> {
    Router::new()
        .route("/", get(get_all_roles))
        .route("/create", post(create_role))
        .route("/{id}/set_permission", post(set_permission))
        .route("/{id}", delete(delete_role))
        .route("/update/{id}", post(update_role))
        .route("/assign", post(assign_role_to_user))
        .route("/{id}/delete_permission", patch(remove_permission))
}
