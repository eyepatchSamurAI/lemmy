#[cfg(feature = "full")]
use crate::schema::secret;

#[derive(Clone)]
#[cfg_attr(feature = "full", derive(Queryable, Identifiable))]
#[cfg_attr(feature = "full", diesel(table_name = person_refresh_token))]
pub struct PersonRefreshToken {
  pub id: i32,
  pub person_id: PersonId,
  pub token_encrypted: String,
  pub expires_at: u64,
  pub issued_at: u64,
  pub client_id: u64
}
