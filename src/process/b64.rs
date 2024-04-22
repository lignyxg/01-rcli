use crate::Base64Format;
use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use std::{fs::File, io::Read};

pub fn process_encode(input: &str, format: Base64Format) -> Result<()> {
    let mut reader = get_reader(input)?;
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;
    let encoded = match format {
        Base64Format::Standard => general_purpose::STANDARD.encode(buf),
        Base64Format::UrlSafe => general_purpose::URL_SAFE_NO_PAD.encode(&buf),
    };
    println!("{}", encoded);
    Ok(())
}

pub fn process_decode(input: &str, format: Base64Format) -> Result<()> {
    let mut reader = get_reader(input)?;
    let mut buf = String::new();
    reader.read_to_string(&mut buf)?;
    let buf = buf.trim(); // avoid accidental new lines
    let decoded = match format {
        Base64Format::Standard => general_purpose::STANDARD.decode(buf)?,
        Base64Format::UrlSafe => general_purpose::URL_SAFE_NO_PAD.decode(buf)?,
    };
    // TODO: decoded might not be String
    let decoded = String::from_utf8(decoded)?;
    println!("{}", decoded);
    Ok(())
}

fn get_reader(input: &str) -> Result<Box<dyn Read>> {
    // 两种不同的数据类型 stdin 和 File 出现在同一个表达式 if...else 中
    // 同一个表达式中需要使用同一种类型，因此这里使用了 trait object 来统一
    let reader: Box<dyn Read> = if input == "-" {
        Box::new(std::io::stdin())
    } else {
        Box::new(File::open(input)?)
    };
    Ok(reader)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_encode() {
        let input = "Cargo.toml";
        let format = Base64Format::Standard;
        assert!(process_encode(input, format).is_ok());
    }

    #[test]
    fn test_process_decode() {
        let input = "fixtures/b64.txt";
        let format = Base64Format::UrlSafe;
        assert!(process_decode(input, format).is_ok());
    }
}
