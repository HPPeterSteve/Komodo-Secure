mod vault;
mod cli;
mod usb_key;

struct Hash {
    value: String,
    status: incomplete,
    security_level: u8,
}
