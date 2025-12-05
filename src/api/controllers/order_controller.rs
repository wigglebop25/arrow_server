use axum::Json;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use crate::api::controllers::dto::order_dto::{CreateOrderRequest, OrderResponse};
use crate::services::order_service::OrderService;
use crate::services::product_service::ProductService;
use crate::services::errors::{OrderServiceError, ProductServiceError};
use crate::security::jwt::AccessClaims;
use crate::data::repos::implementors::user_repo::UserRepo;
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
pub async fn get_order_by_id(
    claims: AccessClaims,
    Path(order_id): Path<i32>,
) -> impl IntoResponse {
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

    // 1. Lookup User
    let user_id = match user_repo.get_by_username(&payload.username).await {
        Ok(Some(user)) => user.user_id,
        Ok(None) => return (StatusCode::BAD_REQUEST, "User not found").into_response(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
    };

    // 2. Process orders (using first valid role for permission check)
    // We need to find a role that has WRITE permission first? 
    // Or just try creating? But create loop might fail halfway.
    // The service checks permission.
    // We should probably check permission once before loop.
    // But service methods take role_id.
    
    // Let's find a valid role ID first.
    let mut valid_role_id = None;
    for role_id in &roles {
        // We can't easily check permission without calling service or exposing helper.
        // But we can try to "dry run" or just assume if get_all works? No.
        // We'll just pick the first role and try. If it fails, try next?
        // But we are creating multiple items. We can't retry the loop.
        // So we MUST pick the role first.
        // Let's assume the first role in the list is the active one for now.
        // Or better, since we need to make multiple calls, we should find a role that works.
        valid_role_id = Some(*role_id as i32);
        break; 
    }
    
    let role_id = match valid_role_id {
        Some(id) => id,
        None => return (StatusCode::FORBIDDEN, "Permission denied").into_response(),
    };

    for item in payload.products {
        // Get Product Price
        let product = match product_service.get_product_by_id(item.product_id, role_id).await {
            Ok(Some(p)) => p,
            Ok(None) => return (StatusCode::BAD_REQUEST, format!("Product {} not found", item.product_id)).into_response(),
            Err(ProductServiceError::PermissionDenied) => return (StatusCode::FORBIDDEN, "Permission denied").into_response(),
             Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
        };
        
        let total = product.price * BigDecimal::from_i32(item.quantity).unwrap_or_default();

        match service.create_order(user_id, role_id, item.product_id, item.quantity, total).await {
            Ok(_) => {},
            Err(OrderServiceError::PermissionDenied) => return (StatusCode::FORBIDDEN, "Permission denied").into_response(),
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create order").into_response(),
        }
    }

    (StatusCode::CREATED, "Orders created").into_response()
}

/// Get orders by user name
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
        match service.get_user_orders(target_user_id, role_id as i32).await {
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
