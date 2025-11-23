use diesel::result;
use diesel_async::RunQueryDsl;
use arrow_server_lib::data::database::*;

async fn setup() -> Result<(), result::Error> {
    let db = Database::new().await;

    let mut conn = db.get_connection().await.expect("Failed to get a database connection");

    use arrow_server_lib::data::models::schema::users::dsl::*;

    diesel::delete(users).execute(&mut conn).await?;

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_create_user() {
    setup().await.expect("Setup failed");
    ()
}