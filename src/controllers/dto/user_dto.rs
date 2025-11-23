use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserDTO {
    pub id: i32,
    pub username: String,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct NewUserDTO {
    pub username: String,
    pub password: String,
}