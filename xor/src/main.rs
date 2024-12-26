mod encfile;
mod scanner;
use std::env;

use scanner::Scanner;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        panic!("Invalid number of arguments. Usage: xor [FILE]");
    }

    let mut scanner = Scanner::new(args[1].to_owned());
    scanner.scan();
}
