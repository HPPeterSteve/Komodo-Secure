use std::fs;
use std::os::unix::fs::PermissionsExt;

pub fn make_readonly(path: &str) {

    let perm = fs::Permissions::from_mode(0o444);

    fs::set_permissions(path, perm)
        .expect("Erro ao aplicar read-only");
}