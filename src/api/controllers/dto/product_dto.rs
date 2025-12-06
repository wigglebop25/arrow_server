use crate::data::models::product::Product;
use bigdecimal::BigDecimal;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct CreateProductRequest {
    pub name: String,
    pub description: Option<String>,
    pub price: BigDecimal,
    pub product_image_uri: Option<String>,
}

#[derive(Deserialize)]
pub struct UpdateProductRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub price: Option<BigDecimal>,
    pub product_image_uri: Option<String>,
}

#[derive(Serialize)]
pub struct ProductResponse {
    pub product_id: i32,
    pub name: String,
    pub description: Option<String>,
    pub price: BigDecimal,
    pub product_image_uri: Option<String>,
}

impl From<Product> for ProductResponse {
    fn from(product: Product) -> Self {
        Self {
            product_id: product.product_id,
            name: product.name,
            description: product.description,
            price: product.price,
            product_image_uri: product.product_image_uri,
        }
    }
}
