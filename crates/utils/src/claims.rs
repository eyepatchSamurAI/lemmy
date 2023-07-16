use crate::error::LemmyError;
use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

type Jwt = String;

const ACCESS_TOKEN_EXPIRE: i64 = 60 * 100 * 10; // 60 * 100 * 15;  // SAMURAI_TODO CHANGE TO ACTUAL MINS
const REFRESH_TOKEN_EXPIRE: i64 = 60 * 100 * 20;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
  /// local_user_id, standard claim by RFC 7519.
  pub sub: i32,
  pub iss: String,
  /// Time when this token was issued as UNIX-timestamp in seconds
  pub iat: i64,
  pub jti: Uuid,
  pub exp: i64,
  pub is_refresh_token: bool,
}

impl Claims {
  pub fn decode(jwt: &str, jwt_secret: &str) -> Result<TokenData<Claims>, LemmyError> {
    let mut validation = Validation::default();
    validation.validate_exp = false;
    validation.required_spec_claims.remove("exp");
    let key = DecodingKey::from_secret(jwt_secret.as_ref());
    Ok(decode::<Claims>(jwt, &key, &validation)?)
  }

  pub fn jwt(local_user_id: i32, jwt_secret: &str, hostname: &str, is_refresh_token: bool) -> Result<Jwt, LemmyError> {
    let now = Utc::now().timestamp();
    let expiration = if is_refresh_token {REFRESH_TOKEN_EXPIRE} else {ACCESS_TOKEN_EXPIRE};
    let my_claims = Claims {
      sub: local_user_id,
      iss: hostname.to_string(),
      iat: now,
      exp: now + expiration,
      jti: Uuid::new_v4(),
      is_refresh_token,
    };

    let key = EncodingKey::from_secret(jwt_secret.as_ref());
    Ok(encode(&Header::default(), &my_claims, &key)?)
  }
}
