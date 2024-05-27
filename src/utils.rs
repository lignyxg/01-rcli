use std::fs::File;
use std::io::Read;

pub fn get_reader(input: &str) -> anyhow::Result<Box<dyn Read>> {
    // 两种不同的数据类型 stdin 和 File 出现在同一个表达式 if...else 中
    // 同一个表达式中需要使用同一种类型，因此这里使用了 trait object 来统一
    let reader: Box<dyn Read> = if input == "-" {
        Box::new(std::io::stdin())
    } else {
        Box::new(File::open(input)?)
    };
    Ok(reader)
}
