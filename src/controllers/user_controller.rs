use axum::http::StatusCode;
use axum::Json;
use axum::body::Body;
use axum::response::{IntoResponse, Response};
use crate::controllers::dto::login_dto::LoginDTO;
use crate::controllers::dto::user_dto::NewUserDTO;
use crate::data::models::user::NewUser;
use crate::data::repos::implementors::user_repo::UserRepo;
use crate::data::repos::traits::repository::Repository;
use crate::services::auth_service::AuthService;

pub async fn register_user(Json(new_user): Json<NewUserDTO>) -> impl IntoResponse {
    let auth = AuthService::new();
    let repo = UserRepo::new();

    let hashed_password = match auth.hash_password(&new_user.password).await {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Error hashing password: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to process password").into_response();
        }
    };

    let new_user = NewUserDTO {
        username: new_user.username,
        password: hashed_password,
    };

    match repo
        .add(NewUser::from(&new_user))
        .await
        {
            Ok(_) => {
                Response::builder()
                    .status(StatusCode::CREATED)
                    .body(Body::from("User created"))
                    .unwrap()
            },
            Err(e) => {
                eprintln!("Error creating user: {}", e);
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from("Failed to create user"))
                    .unwrap()
            }
        }
}

pub async fn login(Json(login_user): Json<LoginDTO>) -> impl IntoResponse {
    let auth = AuthService::new();
    let repo = UserRepo::new();

    if let Some(user) = match repo.get_by_username(&login_user.username).await {
        Ok(opt) => opt,
        Err(e) => {
            eprintln!("Error fetching user: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch user").into_response();
        }
    } {
        match auth.verify_password(&login_user.password, &user.password_hash).await {
            Ok(true) => (StatusCode::OK, "Login successful").into_response(),
            Ok(false) => (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response(),
            Err(e) => {
                eprintln!("Error verifying password: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Failed to verify password").into_response()
            }
        }
    } else {
        (StatusCode::NOT_FOUND, "User not found").into_response()
    }
}