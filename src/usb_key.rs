use std::fs;
use std::path::Path;
#[allow(dead_code)]
// incompleto
pub fn check_usb_key(path: &str) -> bool {

    if Path::new(path).exists() {

        let key = fs::read_to_string(path)
            .unwrap_or_default();

        if key.trim() == "FILEGUARD_KEY" {
            return true;
        }
    }

    false
}