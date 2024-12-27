mod encfile;
mod scanner;
use std::env;

use encfile::EncFile;
use scanner::Scanner;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        panic!("Invalid number of arguments. Usage: xor [TRIMMED FILE] [WHOLE FILE]");
    }

    let mut scanner = Scanner::new(args[1].to_owned());
    let keys = scanner.scan();
    let mut file = EncFile::new(args[2].to_owned());

    print!("\nWriting files...");

    for key in keys {
        file.write_decrypted(key);
    }

    print!("done");
}
