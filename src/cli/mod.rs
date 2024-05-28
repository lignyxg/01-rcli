mod base64;
mod csv;
mod genpass;
mod http;
mod jwt;
mod text;

pub use self::{base64::*, csv::*, genpass::*, http::*, jwt::*, text::*};
use clap::Parser;
use enum_dispatch::enum_dispatch;
use regex::Regex;
use std::ops::Add;
use std::path::{Path, PathBuf};
use time::{Duration, OffsetDateTime};

#[derive(Debug, Parser)]
#[command(name = "rcli", version, author, about, long_about = None)]
pub struct Opts {
    #[command(subcommand)]
    pub cmd: SubCommand,
}

#[derive(Debug, Parser)]
#[enum_dispatch(CmdExecutor)]
pub enum SubCommand {
    #[command(about = "Show CSV, or Convert CSV to other formats")]
    Csv(CsvOpts),
    #[command(name = "genpass", about = "Generate a random password")]
    GenPass(GenPassOpts),
    #[command(subcommand, about = "Base64 encode/decode")]
    Base64(Base64SubCommand),
    #[command(subcommand, about = "Text sign/verify")]
    Text(TextSubCommand),
    #[command(subcommand, about = "HTTP server")]
    Http(HttpSubCommand),
    #[command(subcommand, about = "JWT sign/verify")]
    JWT(JWTSubCommand),
}

fn verify_file(file_name: &str) -> Result<String, &'static str> {
    if file_name == "-" || Path::new(file_name).exists() {
        Ok(file_name.into())
    } else {
        Err("File does not exist")
    }
}

fn verify_path(path: &str) -> Result<PathBuf, &'static str> {
    let p = Path::new(path);
    if p.exists() && p.is_dir() {
        Ok(path.into())
    } else {
        Err("Path does not exist or is not a directory")
    }
}

// 1d4h0m
fn verify_datetime(dt: &str) -> Result<i64, &'static str> {
    let re = Regex::new(r"(?<days>\d+)d(?<hours>\d+)h(?<minutes>\d+)m").unwrap();
    let Some(caps) = re.captures(dt) else {
        return Err("Invalid exp format.");
    };
    let now = OffsetDateTime::now_utc();
    let exp = now
        .add(Duration::days(caps["days"].parse().unwrap()))
        .add(Duration::hours(caps["hours"].parse().unwrap()))
        .add(Duration::minutes(caps["minutes"].parse().unwrap()));
    Ok(exp.unix_timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_input_file() {
        assert_eq!(verify_file("-"), Ok("-".into()));
        assert_eq!(verify_file("*"), Err("File does not exist"));
        assert_eq!(verify_file("Cargo.toml"), Ok("Cargo.toml".into()));
        assert_eq!(verify_file("non-exist"), Err("File does not exist"));
    }
    #[test]
    fn test_regex() {
        let dt = "10d5h20m";
        let re = Regex::new(r"^(?<days>\d+)d(?<hours>\d+)h(?<minutes>\d+)m$").unwrap();
        let caps = re.captures(dt).expect("not match");
        eprintln!("{:?}", caps);
        assert_eq!(&caps["days"], "10");
        assert_eq!(&caps["hours"], "5");
        assert_eq!(&caps["minutes"], "20");
    }
    #[test]
    fn test_verify_datetime() {
        let dt = "1d0h0m";
        let ts = verify_datetime(dt).expect("should work");
        let now = OffsetDateTime::now_utc();
        assert_eq!(
            now.date().add(Duration::days(1)),
            OffsetDateTime::from_unix_timestamp(ts).unwrap().date()
        );
    }
}
