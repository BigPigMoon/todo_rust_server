use bcrypt::{hash, verify, DEFAULT_COST};
use jwt_simple::prelude::{Duration, *};
use rocket::{
    http::Status,
    serde::{json::Json, Deserialize, Serialize},
    State,
};
use sea_orm::{ActiveValue, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use std::env;

use crate::{
    entities::{prelude::User, user},
    guards::jwt_guard::JwtData,
};

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
struct Login<'r> {
    email: &'r str,
    password: &'r str,
}

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
struct Register<'r> {
    email: &'r str,
    password: &'r str,
}

#[derive(Serialize)]
#[serde(crate = "rocket::serde")]
struct Tokens {
    access: String,
    refresh: String,
}

#[post("/signin", data = "<dto>")]
async fn signin(
    db: &State<DatabaseConnection>,
    dto: Json<Login<'_>>,
) -> Result<Json<Tokens>, Status> {
    let db = db as &DatabaseConnection;

    let user = match User::find()
        .filter(user::Column::Email.eq(dto.email))
        .one(db)
        .await
    {
        Err(_) => return Err(Status::InternalServerError),
        Ok(res) => match res {
            None => return Err(Status::NotFound),
            Some(user) => user,
        },
    };

    let valid = verify(dto.password, &user.password_hash).unwrap();
    if !valid {
        return Err(Status::Forbidden);
    }

    let key = env::var("JWT_KEY").expect("JWT_KEY is not set in .env file");
    let key = HS256Key::from_bytes(key.as_bytes());

    let refresh = gen_token(
        &key,
        user.id,
        user.email.to_string(),
        "refresh".to_string(),
        Duration::from_days(14),
    );

    // TODO: write hash of refresh token into user
    let mut user: user::ActiveModel = user.into();

    user.refresh_hash = ActiveValue::Set(Some(refresh.clone()));

    let user = user.update(db).await.unwrap();

    Ok(Json(Tokens {
        access: gen_token(
            &key,
            user.id,
            user.email.to_string(),
            "access".to_string(),
            Duration::from_mins(15),
        )
        .to_owned(),
        refresh: refresh.to_owned(),
    }))
}

#[post("/signup", data = "<dto>")]
async fn signup(
    db: &State<DatabaseConnection>,
    dto: Json<Register<'_>>,
) -> Result<Json<Tokens>, Status> {
    let db = db as &DatabaseConnection;

    let hashed_password = hash(dto.password, DEFAULT_COST).unwrap();

    let new_user = user::ActiveModel {
        email: ActiveValue::Set(dto.email.to_owned()),
        password_hash: ActiveValue::Set(hashed_password),
        ..Default::default()
    };

    let res = match User::insert(new_user).exec(db).await {
        Ok(res) => res,
        Err(_) => return Err(Status::Forbidden),
    };

    let key = env::var("JWT_KEY").expect("JWT_KEY is not set in .env file");
    let key = HS256Key::from_bytes(key.as_bytes());

    let refresh = gen_token(
        &key,
        res.last_insert_id,
        dto.email.to_string(),
        "refresh".to_string(),
        Duration::from_days(14),
    );

    let mut user: user::ActiveModel = User::find_by_id(res.last_insert_id)
        .one(db)
        .await
        .unwrap()
        .unwrap()
        .into();

    user.refresh_hash = ActiveValue::Set(Some(refresh.clone()));

    Ok(Json(Tokens {
        access: gen_token(
            &key,
            res.last_insert_id,
            dto.email.to_string(),
            "access".to_string(),
            Duration::from_mins(15),
        )
        .to_owned(),
        refresh: refresh.to_owned(),
    }))
}

fn gen_token(key: &HS256Key, uid: i32, email: String, scope: String, duration: Duration) -> String {
    let access_data = JwtData { uid, email, scope };

    let claims = Claims::with_custom_claims(access_data, duration);

    key.authenticate(claims).unwrap()
}

#[post("/logout")]
async fn logout(_db: &State<DatabaseConnection>, cred: JwtData) -> Status {
    println!("{:?}", cred);
    Status::Ok
}

#[post("/refresh")]
async fn refresh(db: &State<DatabaseConnection>, cred: JwtData) -> Result<Json<Tokens>, Status> {
    if cred.scope != "refresh" {
        return Err(Status::BadRequest);
    }

    let db = db as &DatabaseConnection;

    let user = match User::find_by_id(cred.uid).one(db).await {
        Ok(user) => user.unwrap(),
        Err(_) => return Err(Status::NotFound),
    };

    let key = env::var("JWT_KEY").expect("JWT_KEY is not set in .env file");
    let key = HS256Key::from_bytes(key.as_bytes());

    Ok(Json(Tokens {
        access: "slkdjf".to_string(),
        refresh: "sdfklj".to_string(),
    }))
}

pub fn routes() -> Vec<rocket::Route> {
    routes![signin, signup, logout, refresh]
}
