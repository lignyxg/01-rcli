use clap::Parser;
use std::path::Path;

#[derive(Debug, Parser)]
#[command(name = "rcli", version, author, about, long_about = None)]
pub struct Opts {
    #[command(subcommand)]
    pub cmd: SubCommand,
}

#[derive(Debug, Parser)]
pub enum SubCommand {
    #[command(about = "Show CSV, or Convert CSV to other formats")]
    Csv(CsvOpts),
}

#[derive(Debug, Parser)]
pub struct CsvOpts {
    #[arg(short, long, value_parser = verify_input_file)]
    pub input: String,
    /**
    default_value 表示这个值需要转换,
    比如"output.json"是一个 &str, 它实现了From<T> trait,
    可以转换为 String, "output.json".into()
     */
    #[arg(short, long, default_value = "output.json")]
    pub output: String,
    // default_value_t 表示就是这个字面值, 不需要转换处理
    #[arg(short, long, default_value_t = ',')]
    pub delimiter: char,
    #[arg(long, default_value_t = true)]
    pub header: bool,
}

fn verify_input_file(file_name: &str) -> Result<String, &'static str> {
    if Path::new(file_name).exists() {
        Ok(file_name.into())
    } else {
        Err("File does not exists")
    }
}
