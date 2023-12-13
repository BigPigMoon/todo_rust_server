extern crate dotenv;

#[macro_use]
extern crate rocket;

mod entities;
mod guards;
mod routes;

use dotenv::dotenv;
use rocket_cors::{AllowedHeaders, AllowedOrigins, CorsOptions};
use routes::auth;
use routes::todo;
use sea_orm::{Database, DatabaseConnection, DbErr};
use std::env;

#[get("/")]
fn index() -> &'static str {
    "Todo App index page"
}

async fn set_up_db(conn_str: &str) -> Result<DatabaseConnection, DbErr> {
    let db = Database::connect(conn_str).await?;

    Ok(db)
}

#[launch]
async fn rocket() -> _ {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL is not set in .env file");

    let db = match set_up_db(&database_url).await {
        Ok(db) => db,
        Err(err) => panic!("{}", err),
    };

    let cors = CorsOptions {
        allowed_origins: AllowedOrigins::all(),
        allowed_headers: AllowedHeaders::all(),
        allow_credentials: true,
        ..Default::default()
    }
    .to_cors()
    .expect("failde to create CORS config");

    rocket::build()
        .attach(cors)
        .manage(db)
        .mount("/", routes![index])
        .mount("/todo", todo::routes())
        .mount("/auth", auth::routes())
}
