use crate::cli::verify_datetime;
use crate::{process_jwt_sign, process_jwt_verify, CmdExecutor};
use clap::Parser;
use enum_dispatch::enum_dispatch;
use serde::{Deserialize, Serialize};

#[derive(Debug, Parser)]
#[enum_dispatch(CmdExecutor)]
pub enum JWTSubCommand {
    #[command(about = "Sign a JWT(Json Web Token)")]
    Sign(JWTSignOpts),
    #[command(about = "Verify a JWT")]
    Verify(JWTVerifyOpts),
}

#[derive(Debug, Parser, Serialize, Deserialize)]
pub struct JWTSignOpts {
    /// Subject (whom token refers to)
    #[arg(long)]
    pub sub: String,
    /// Audience
    #[arg(long)]
    pub aud: String,
    /// Expiration
    #[arg(long, value_parser = verify_datetime)]
    pub exp: i64,
}

#[derive(Debug, Parser, Serialize, Deserialize)]
pub struct JWTVerifyOpts {
    /// JWT to verify
    #[arg(short, long)]
    pub token: String,
    #[arg(short, long)]
    pub aud: String,
}

impl CmdExecutor for JWTSignOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let token = process_jwt_sign(self.sub, self.aud, self.exp)?;
        println!("token:{}", token);
        Ok(())
    }
}

impl CmdExecutor for JWTVerifyOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let verified = process_jwt_verify(self.token, self.aud)?;
        println!("{verified}");
        Ok(())
    }
}
