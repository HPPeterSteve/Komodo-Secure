mod cli;
mod vault;
mod immutable;
mod usb_key;

fn main() {

    let args = cli::get_args();

    match args.command.as_str() {

        "create-vault" => {
            vault::create(&args.path);
        }

        "add-file" => {
            vault::add_file(&args.path, &args.file);
        }

        _ => {
            cli::help();
        }
    }
}