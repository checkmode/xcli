//! Initialize a fresh panel database. The password is read from stdin.
use std::io::Read;
use std::path::PathBuf;
use xcli_panel_provision::initialize_new_file;
use zeroize::Zeroizing;

fn run() -> Result<(), ()> {
    let mut args = std::env::args_os().skip(1);
    if args.next().as_deref() != Some(std::ffi::OsStr::new("--experimental"))
        || args.next().as_deref() != Some(std::ffi::OsStr::new("--database"))
    {
        return Err(());
    }
    let path = PathBuf::from(args.next().ok_or(())?);
    if args.next().is_some() || !path.is_absolute() {
        return Err(());
    }
    let mut password = Zeroizing::new(Vec::new());
    std::io::stdin()
        .lock()
        .take(1026)
        .read_to_end(&mut password)
        .map_err(|_| ())?;
    if password.len() > 1024 {
        return Err(());
    }
    if password.last() == Some(&b'\n') {
        password.pop();
        if password.last() == Some(&b'\r') {
            password.pop();
        }
    }
    let text = std::str::from_utf8(&password).map_err(|_| ())?;
    if text.chars().any(char::is_control) {
        return Err(());
    }
    initialize_new_file(&path, text).map_err(|_| ())
}
fn main() {
    if run().is_err() {
        eprintln!("初始化失败；请检查密码、目标目录和现有文件");
        std::process::exit(1);
    }
}
