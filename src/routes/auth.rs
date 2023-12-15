use bcrypt::{hash, verify, DEFAULT_COST};
use jwt_simple::prelude::{Duration, *};
use rocket::{
    http::Status,
    serde::{json::Json, Deserialize, Serialize},
    State,
};
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter,
};
use std::env;

use crate::{
    entities::{prelude::User, user},
    guards::{jwt_access::JwtAccessToken, jwt_refresh::JwtRefreshToken},
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

    user.update(db).await.unwrap();

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
    let access_data = JwtAccessToken { uid, email, scope };

    let claims = Claims::with_custom_claims(access_data, duration);

    key.authenticate(claims).unwrap()
}

#[post("/logout")]
async fn logout(_db: &State<DatabaseConnection>, cred: JwtAccessToken) -> Status {
    println!("{:?}", cred);

    let db = _db as &DatabaseConnection;

    let mut user: user::ActiveModel = match User::find_by_id(cred.uid).one(db).await {
        Ok(user) => user.unwrap(),
        Err(_) => return Status::NotFound,
    }
    .into();

    user.refresh_hash = ActiveValue::Set(None);

    user.update(db).await.unwrap();

    Status::Ok
}

#[post("/refresh")]
async fn refresh_token(
    db: &State<DatabaseConnection>,
    refresh: JwtRefreshToken,
) -> Result<Json<Tokens>, Status> {
    let db = db as &DatabaseConnection;

    let key = env::var("JWT_KEY").expect("JWT_KEY is not set in .env file");
    let key = HS256Key::from_bytes(key.as_bytes());

    let cred = key
        .verify_token::<JwtAccessToken>(
            &refresh.token,
            Some(VerificationOptions {
                accept_future: false,
                time_tolerance: Some(Duration::from_secs(0)),
                ..Default::default()
            }),
        )
        .unwrap()
        .custom;

    let user = match User::find_by_id(cred.uid).one(db).await {
        Ok(user) => user.unwrap(),
        Err(_) => return Err(Status::NotFound),
    };

    // TODO: check if storage refresh and requested refresh are equeal

    match user.refresh_hash {
        Some(token) if token.eq(&refresh.token) => return Err(Status::Forbidden),
        Some(_) => {}
        None => return Err(Status::Unauthorized),
    };

    // TODO: generate new refresh

    // TODO: write new refresh into database

    // TODO: return new refresh and access

    Ok(Json(Tokens {
        access: "slkdjf".to_string(),
        refresh: "sdfklj".to_string(),
    }))
}

pub fn routes() -> Vec<rocket::Route> {
    routes![signin, signup, logout, refresh_token]
}
