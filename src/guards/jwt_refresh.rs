use std::env;

use crate::guards::jwt_access::JwtAccessToken;
use jwt_simple::prelude::{Duration, *};
use rocket::{
    http::Status,
    request::{FromRequest, Outcome, Request},
    serde::{Deserialize, Serialize},
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct JwtRefreshToken {
    pub token: String,
}

#[derive(Debug)]
pub enum AuthError {
    Invalid,
    Missing,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for JwtRefreshToken {
    type Error = AuthError;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        fn decode_token(token: &str) -> Outcome<JwtRefreshToken, AuthError> {
            let options = get_options();

            let key = env::var("JWT_KEY").expect("JWT_KEY is not set in .env file");
            let key = HS256Key::from_bytes(key.as_bytes());

            match key.verify_token::<JwtAccessToken>(token, Some(options)) {
                Ok(data) if data.custom.scope == "refresh" => Outcome::Success(JwtRefreshToken {
                    token: token.to_owned(),
                }),
                _ => Outcome::Error((Status::Unauthorized, AuthError::Invalid)),
            }
        }

        match req.headers().get_one("Authorization") {
            None => Outcome::Error((Status::BadRequest, AuthError::Missing)),
            Some(bearer_token) => match bearer_token.split(' ').last() {
                Some(token) => decode_token(token),
                _ => Outcome::Error((Status::Unauthorized, AuthError::Invalid)),
            },
        }
    }
}

fn get_options() -> VerificationOptions {
    let mut options = VerificationOptions::default();

    options.accept_future = false;
    options.time_tolerance = Some(Duration::from_secs(0));

    options
}
