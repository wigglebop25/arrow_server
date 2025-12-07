use crate::data::models::order::Order;
use bigdecimal::BigDecimal;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct OrderItemRequest {
    pub product_id: i32,
    pub quantity: i32,
}

#[derive(Deserialize)]
pub struct CreateOrderRequest {
    pub products: Vec<OrderItemRequest>,
}

#[derive(Serialize, Deserialize)]
pub struct OrderResponse {
    pub order_id: i32,
    pub user_id: i32,
    pub product_id: i32,
    pub quantity: i32,
    pub total_amount: BigDecimal,
    pub status: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

impl From<Order> for OrderResponse {
    fn from(order: Order) -> Self {
        Self {
            order_id: order.order_id,
            user_id: order.user_id,
            product_id: order.product_id,
            quantity: order.quantity,
            total_amount: order.total_amount,
            status: order.status,
            created_at: order.created_at.map(|d| d.to_string()),
            updated_at: order.updated_at.map(|d| d.to_string()),
        }
    }
}
