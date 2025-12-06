use crate::api::controllers::dto::order_dto::{CreateOrderRequest, OrderResponse};
use crate::data::repos::implementors::user_repo::UserRepo;
use crate::security::jwt::AccessClaims;
use crate::services::errors::{OrderServiceError, ProductServiceError};
use crate::services::order_service::OrderService;
use crate::services::product_service::ProductService;
use axum::Json;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use bigdecimal::BigDecimal;
use bigdecimal::FromPrimitive;

// TODO: Add get orders by role route which returns all orders of users with a specific role returns a list of orders filtered by role

/// Get all orders
pub async fn get_all_orders(claims: AccessClaims) -> impl IntoResponse {
    let service = OrderService::new();
    let roles = claims.roles.unwrap_or_default();

    if roles.is_empty() {
        return (StatusCode::FORBIDDEN, "Permission denied").into_response();
    }

    for role_id in roles {
        match service.get_all_orders(role_id as i32).await {
            Ok(orders) => {
                let response: Vec<OrderResponse> = orders
                    .unwrap_or_default()
                    .into_iter()
                    .map(OrderResponse::from)
                    .collect();
                return (StatusCode::OK, Json(response)).into_response();
            }
            Err(OrderServiceError::PermissionDenied) => continue,
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
        }
    }

    (StatusCode::FORBIDDEN, "Permission denied").into_response()
}

/// Get order by ID
pub async fn get_order_by_id(claims: AccessClaims, Path(order_id): Path<i32>) -> impl IntoResponse {
    let service = OrderService::new();
    let roles = claims.roles.unwrap_or_default();

    if roles.is_empty() {
        return (StatusCode::FORBIDDEN, "Permission denied").into_response();
    }

    for role_id in roles {
        match service.get_order_by_id(order_id, role_id as i32).await {
            Ok(Some(order)) => {
                return (StatusCode::OK, Json(OrderResponse::from(order))).into_response();
            }
            Ok(None) => return (StatusCode::NOT_FOUND, "Order not found").into_response(),
            Err(OrderServiceError::PermissionDenied) => continue,
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
        }
    }

    (StatusCode::FORBIDDEN, "Permission denied").into_response()
}

/// Create a new order
pub async fn create_order(
    claims: AccessClaims,
    Json(payload): Json<CreateOrderRequest>,
) -> impl IntoResponse {
    let service = OrderService::new();
    let product_service = ProductService::new();
    let user_repo = UserRepo::new();
    let roles = claims.roles.unwrap_or_default();

    if roles.is_empty() {
        return (StatusCode::FORBIDDEN, "Permission denied").into_response();
    }

    let user_id = match user_repo.get_by_username(&payload.username).await {
        Ok(Some(user)) => user.user_id,
        Ok(None) => return (StatusCode::BAD_REQUEST, "User not found").into_response(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
    };

    let valid_role_id = roles.into_iter().next();

    let role_id = match valid_role_id {
        Some(id) => id as i32,
        None => return (StatusCode::FORBIDDEN, "Permission denied").into_response(),
    };

    for item in payload.products {
        // Get Product Price
        let product = match product_service
            .get_product_by_id(item.product_id, role_id)
            .await
        {
            Ok(Some(p)) => p,
            Ok(None) => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("Product {} not found", item.product_id),
                )
                    .into_response();
            }
            Err(ProductServiceError::PermissionDenied) => {
                return (StatusCode::FORBIDDEN, "Permission denied").into_response();
            }
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
        };

        let total = product.price * BigDecimal::from_i32(item.quantity).unwrap_or_default();

        match service
            .create_order(user_id, role_id, item.product_id, item.quantity, total)
            .await
        {
            Ok(_) => {}
            Err(OrderServiceError::PermissionDenied) => {
                return (StatusCode::FORBIDDEN, "Permission denied").into_response();
            }
            Err(_) => {
                return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create order")
                    .into_response();
            }
        }
    }

    (StatusCode::CREATED, "Orders created").into_response()
}

/// Get orders by username
pub async fn get_user_orders_by_name(
    claims: AccessClaims,
    Path(username): Path<String>,
) -> impl IntoResponse {
    let service = OrderService::new();
    let user_repo = UserRepo::new();
    let roles = claims.roles.unwrap_or_default();

    if roles.is_empty() {
        return (StatusCode::FORBIDDEN, "Permission denied").into_response();
    }

    // Lookup User
    let target_user_id = match user_repo.get_by_username(&username).await {
        Ok(Some(user)) => user.user_id,
        Ok(None) => return (StatusCode::NOT_FOUND, "User not found").into_response(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
    };

    for role_id in roles {
        match service
            .get_user_orders(target_user_id, role_id as i32)
            .await
        {
            Ok(orders) => {
                let response: Vec<OrderResponse> = orders
                    .unwrap_or_default()
                    .into_iter()
                    .map(OrderResponse::from)
                    .collect();
                return (StatusCode::OK, Json(response)).into_response();
            }
            Err(OrderServiceError::PermissionDenied) => continue,
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
        }
    }

    (StatusCode::FORBIDDEN, "Permission denied").into_response()
}
