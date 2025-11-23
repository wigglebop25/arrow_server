use async_trait::async_trait;
use diesel::prelude::*;
use diesel::result;
use diesel_async::{AsyncConnection, AsyncMysqlConnection, RunQueryDsl};
use diesel_async::pooled_connection::deadpool::Object;
use diesel_async::scoped_futures::ScopedFutureExt;
use crate::data::database::Database;
use crate::data::models::user::{NewUser, UpdateUser, User};
use crate::data::repos::traits::repository::Repository;

pub struct UserRepo {}
impl UserRepo {
    pub fn new() -> Self {
        UserRepo {}
    }
    // TODO: Add any additional methods specific to UserRepo if needed
    
    pub async fn get_by_username(&self, username_query: &str) -> Result<Option<User>, result::Error> {
        use crate::data::models::schema::users::dsl::{users, username};

        let db = Database::new().await;

        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        match users
            .filter(username.eq(username_query))
            .first::<User>(&mut conn)
            .await
        {
            Ok(value) => Ok(Some(value)),
            Err(result::Error::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }
}
// TODO: Create tests
#[async_trait]
impl Repository for UserRepo {
    type Id = i32;
    type Item = User;
    type NewItem<'a> = NewUser<'a>;
    type UpdateForm<'a> = UpdateUser<'a>;

    async fn get_all(&self) -> Result<Option<Vec<Self::Item>>, result::Error> {
        use crate::data::models::schema::users::dsl::users;

        let db = Database::new().await;

        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        match users.load::<Self::Item>(&mut conn).await {
            Ok(value) if value.is_empty() => Ok(None),
            Ok(value) => Ok(Some(value)),
            Err(result::Error::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }
    async fn get_by_id(&self, id: Self::Id) -> Result<Option<Self::Item>, result::Error> {
        use crate::data::models::schema::users::dsl::{users, user_id};

        let db = Database::new().await;

        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        match users
            .filter(user_id.eq(id))
            .first::<Self::Item>(&mut conn)
            .await
        {
            Ok(value) => Ok(Some(value)),
            Err(result::Error::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }
    async fn add<'a>(&self, item: Self::NewItem<'a>) -> Result<(), result::Error> {
        use crate::data::models::schema::users::dsl::users;

        let db = Database::new().await;

        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        match conn
            .transaction(|connection|
                async move {
                    diesel::insert_into(users)
                        .values(&item)
                        .execute(connection)
                        .await?;
                    Ok(())
                }
                .scope_boxed()
        ).await {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }
    async fn update<'a>(
        &self,
        id: Self::Id,
        item: Self::UpdateForm<'a>,
    ) -> Result<(), result::Error> {
        use crate::data::models::schema::users::dsl::{users, user_id};

        let db = Database::new().await;

        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        match conn
            .transaction(|connection|
                async move {
                    diesel::update(users.filter(user_id.eq(id)))
                        .set(&item)
                        .execute(connection)
                        .await?;
                    Ok(())
                }
                .scope_boxed()
        ).await {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }
    async fn delete(&self, id: Self::Id) -> Result<(), result::Error> {
        use crate::data::models::schema::users::dsl::{users, user_id};

        let db = Database::new().await;

        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        match conn
            .transaction(|connection|
                async move {
                    diesel::delete(users.filter(user_id.eq(id)))
                        .execute(connection)
                        .await?;
                    Ok(())
                }
                .scope_boxed()
        ).await {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }
}