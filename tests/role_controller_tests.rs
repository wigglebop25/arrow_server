use arrow_server_lib::api::controllers::role_controller::{
    assign_role_to_user, create_role, delete_role, get_all_roles, get_role_by_name,
    remove_permission, set_permission, update_role,
};
use arrow_server_lib::data::database::Database;
use arrow_server_lib::data::models::user::NewUser;
use arrow_server_lib::data::models::user_roles::NewUserRole;
use arrow_server_lib::data::repos::implementors::user_repo::UserRepo;
use arrow_server_lib::data::repos::implementors::user_role_repo::UserRoleRepo;
use arrow_server_lib::data::repos::traits::repository::Repository;
use arrow_server_lib::security::auth::AuthService;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::{delete, get, patch, post};
use diesel::result;
use diesel_async::RunQueryDsl;
use http_body_util::BodyExt;
use serde_json::json;
use tower::ServiceExt;

async fn setup() -> Result<(), result::Error> {
    let db = Database::new().await;

    let mut conn = db
        .get_connection()
        .await
        .expect("Failed to get a database connection");

    use arrow_server_lib::data::models::schema::order_products::dsl::order_products;
    use arrow_server_lib::data::models::schema::orders::dsl::orders;
    use arrow_server_lib::data::models::schema::products::dsl::products;
    use arrow_server_lib::data::models::schema::user_roles::dsl::user_roles;
    use arrow_server_lib::data::models::schema::users::dsl::users;

    diesel::delete(order_products).execute(&mut conn).await?;
    diesel::delete(orders).execute(&mut conn).await?;
    diesel::delete(products).execute(&mut conn).await?;
    diesel::delete(user_roles).execute(&mut conn).await?;
    diesel::delete(users).execute(&mut conn).await?;

    Ok(())
}

async fn create_test_user(username: &str) -> i32 {
    let auth = AuthService::new();
    let repo = UserRepo::new();

    let hashed = auth
        .hash_password("testpass")
        .await
        .expect("Hashing failed");

    let test_user = NewUser {
        username,
        password_hash: &hashed,
    };

    repo.add(test_user).await.expect("Failed to add user");

    repo.get_by_username(username)
        .await
        .expect("Failed to get user")
        .expect("User not found")
        .user_id
}

async fn create_test_role(user_id: i32, name: &str) -> i32 {
    let repo = UserRoleRepo::new();

    let new_role = NewUserRole {
        user_id,
        name,
        description: Some("Test role"),
    };

    repo.add(new_role).await.expect("Failed to add role");

    repo.get_by_name(name)
        .await
        .expect("Failed to get role")
        .expect("Role not found")
        .role_id
}

fn app() -> Router {
    Router::new()
        .route("/roles", get(get_all_roles))
        .route("/roles", post(create_role))
        .route("/roles/name/{name}", get(get_role_by_name))
        .route("/roles/{id}", patch(update_role))
        .route("/roles/{id}", delete(delete_role))
        .route("/roles/{id}/permission", post(set_permission))
        .route("/roles/{id}/permission", delete(remove_permission))
        .route("/roles/assign", post(assign_role_to_user))
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_all_roles_empty() {
    setup().await.expect("Setup failed");

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/roles")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body, json!([]));
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_all_roles_with_data() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user("role_test_user").await;
    let _ = create_test_role(user_id, "admin_role").await;
    let _ = create_test_role(user_id, "user_role").await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/roles")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let roles = body.as_array().unwrap();
    assert_eq!(roles.len(), 2);
}

#[tokio::test]
#[serial_test::serial]
async fn test_create_role_success() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user("create_role_user").await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/roles")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "user_id": user_id,
                        "name": "new_role",
                        "description": "A new test role"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    // Verify creation
    let repo = UserRoleRepo::new();
    let role = repo
        .get_by_name("new_role")
        .await
        .expect("Query failed")
        .expect("Role not found");
    assert_eq!(role.name, "new_role");
}

#[tokio::test]
#[serial_test::serial]
async fn test_create_role_user_not_found() {
    setup().await.expect("Setup failed");

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/roles")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "user_id": 99999,
                        "name": "invalid_role",
                        "description": null
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_role_by_name() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user("get_role_user").await;
    let _ = create_test_role(user_id, "test_role").await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/roles/name/test_role")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["name"], "test_role");
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_role_by_name_not_found() {
    setup().await.expect("Setup failed");

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/roles/name/nonexistent")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[serial_test::serial]
async fn test_update_role() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user("update_role_user").await;
    let role_id = create_test_role(user_id, "update_test_role").await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(&format!("/roles/{}", role_id))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "name": "updated_role_name",
                        "description": "Updated description"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Verify update
    let repo = UserRoleRepo::new();
    let role = repo
        .get_by_id(role_id)
        .await
        .expect("Query failed")
        .expect("Role not found");
    assert_eq!(role.name, "updated_role_name");
    assert_eq!(role.description, Some("Updated description".to_string()));
}

#[tokio::test]
#[serial_test::serial]
async fn test_update_role_not_found() {
    setup().await.expect("Setup failed");

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/roles/99999")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "name": "new_name"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[serial_test::serial]
async fn test_delete_role() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user("delete_role_user").await;
    let role_id = create_test_role(user_id, "delete_test_role").await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(&format!("/roles/{}", role_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Verify deletion
    let repo = UserRoleRepo::new();
    let deleted = repo.get_by_id(role_id).await.expect("Query failed");
    assert!(deleted.is_none());
}

#[tokio::test]
#[serial_test::serial]
async fn test_delete_role_not_found() {
    setup().await.expect("Setup failed");

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/roles/99999")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[serial_test::serial]
async fn test_set_permission() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user("perm_user").await;
    let role_id = create_test_role(user_id, "perm_test_role").await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&format!("/roles/{}/permission", role_id))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "permission": "ADMIN"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Verify permission set
    let repo = UserRoleRepo::new();
    let role = repo
        .get_by_id(role_id)
        .await
        .expect("Query failed")
        .expect("Role not found");
    let perm = role.get_permissions().expect("No permissions");
    assert_eq!(perm.as_str(), "ADMIN");
}

#[tokio::test]
#[serial_test::serial]
async fn test_set_permission_invalid() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user("invalid_perm_user").await;
    let role_id = create_test_role(user_id, "invalid_perm_role").await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&format!("/roles/{}/permission", role_id))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "permission": "INVALID_PERMISSION"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial_test::serial]
async fn test_set_permission_role_not_found() {
    setup().await.expect("Setup failed");

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/roles/99999/permission")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "permission": "READ"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[serial_test::serial]
async fn test_assign_role_to_user() {
    setup().await.expect("Setup failed");

    let _ = create_test_user("assign_user").await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/roles/assign")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "username": "assign_user",
                        "role_name": "assigned_role"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    // Verify role was assigned
    let repo = UserRoleRepo::new();
    let role = repo
        .get_by_name("assigned_role")
        .await
        .expect("Query failed")
        .expect("Role not found");
    assert_eq!(role.name, "assigned_role");
}

#[tokio::test]
#[serial_test::serial]
async fn test_assign_role_user_not_found() {
    setup().await.expect("Setup failed");

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/roles/assign")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "username": "nonexistent_user",
                        "role_name": "some_role"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[serial_test::serial]
async fn test_set_all_permission_types() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user("all_perms_user").await;
    let role_id = create_test_role(user_id, "all_perms_role").await;

    let repo = UserRoleRepo::new();

    for perm in ["READ", "WRITE", "DELETE", "ADMIN"] {
        let app = app();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/roles/{}/permission", role_id))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "permission": perm
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Failed to set {} permission",
            perm
        );

        let role = repo
            .get_by_id(role_id)
            .await
            .expect("Query failed")
            .expect("Role not found");
        assert_eq!(role.get_permissions().unwrap().as_str(), perm);
    }
}
