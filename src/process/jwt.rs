use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

const SECRET: &str = "this_is_secret";

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub aud: String,
    pub exp: i64,
}

impl Display for Claims {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", serde_json::to_string(self).unwrap())
    }
}

pub fn process_jwt_sign(sub: String, aud: String, exp: i64) -> anyhow::Result<String> {
    let token = jsonwebtoken::encode(
        &Header::default(),
        &Claims { sub, aud, exp },
        &EncodingKey::from_secret(SECRET.as_ref()),
    )?;
    Ok(token)
}

pub fn process_jwt_verify(token: String, aud: String) -> anyhow::Result<bool> {
    let mut valid = Validation::new(Algorithm::HS256);
    valid.set_audience(&[aud]);
    // valid.set_required_spec_claims(&["exp", "sub", "aud"]);
    let token_data = jsonwebtoken::decode::<Claims>(
        token.as_ref(),
        &DecodingKey::from_secret(SECRET.as_ref()),
        &valid,
    )?;
    println!("token data:{}", token_data.claims);
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_round_trip() -> anyhow::Result<()> {
        // may fail due to fixed timestamp in the future
        let (sub, aud, exp) = ("acme".to_string(), "device1".to_string(), 1719954343);
        let token = process_jwt_sign(sub, aud.clone(), exp)?;
        assert!(process_jwt_verify(token, aud).is_ok());
        Ok(())
    }
}
