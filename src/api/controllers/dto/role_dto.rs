use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RoleDTO {
    pub name: String,
    pub description: Option<String>,
    pub permissions: String,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}
