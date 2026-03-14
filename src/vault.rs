use std::env;

pub struct Args {
    pub command: String,
    pub path: String,
    pub file: String,
}

pub fn get_args() -> Args {

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        help();
        std::process::exit(0);
    }

    let command = args.get(1).unwrap_or(&"".to_string()).clone();
    let path = args.get(2).unwrap_or(&"".to_string()).clone();
    let file = args.get(3).unwrap_or(&"".to_string()).clone();

    Args { command, path, file }
}

pub fn help() {

    println!("Comandos:");
    println!("create-vault <path>");
    println!("add-file <vault> <file>");
}