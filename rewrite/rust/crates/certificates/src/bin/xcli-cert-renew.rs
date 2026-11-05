//! Experimental Certbot deploy-hook executable. Not installed automatically.
#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::OsString;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Component, Path, PathBuf};
    use xcli_certificates::{
        bundle::{publish_dropped, PublishError},
        renewal::{matches_lineage, read_pair},
    };

    struct Args {
        root: PathBuf,
        lineage: String,
        domain: String,
        target: PathBuf,
        uid: u32,
        gid: u32,
        output_gid: u32,
    }
    fn numeric(value: Option<OsString>) -> Result<u32, &'static str> {
        value
            .and_then(|v| v.into_string().ok())
            .and_then(|v| v.parse::<u32>().ok())
            .filter(|v| *v != 0)
            .ok_or("参数无效")
    }
    fn arguments() -> Result<Args, &'static str> {
        let mut input = std::env::args_os().skip(1);
        if input.next().as_deref() != Some(std::ffi::OsStr::new("--experimental")) {
            return Err("测试程序需要 --experimental");
        }
        let mut root = None;
        let mut lineage = None;
        let mut domain = None;
        let mut target = None;
        let mut uid = None;
        let mut gid = None;
        let mut output_gid = None;
        while let Some(name) = input.next() {
            let value = input.next().ok_or("缺少参数")?;
            match name.to_str() {
                Some("--certbot-root") if root.is_none() => root = Some(PathBuf::from(value)),
                Some("--lineage") if lineage.is_none() => {
                    lineage = Some(value.into_string().map_err(|_| "参数无效")?)
                }
                Some("--domain") if domain.is_none() => {
                    domain = Some(value.into_string().map_err(|_| "参数无效")?)
                }
                Some("--target") if target.is_none() => target = Some(PathBuf::from(value)),
                Some("--validator-uid") if uid.is_none() => uid = Some(numeric(Some(value))?),
                Some("--validator-gid") if gid.is_none() => gid = Some(numeric(Some(value))?),
                Some("--output-gid") if output_gid.is_none() => {
                    output_gid = Some(numeric(Some(value))?)
                }
                _ => return Err("未知或重复参数"),
            }
        }
        Ok(Args {
            root: root.ok_or("缺少参数")?,
            lineage: lineage.ok_or("缺少参数")?,
            domain: domain.ok_or("缺少参数")?,
            target: target.ok_or("缺少参数")?,
            uid: uid.ok_or("缺少参数")?,
            gid: gid.ok_or("缺少参数")?,
            output_gid: output_gid.ok_or("缺少参数")?,
        })
    }
    fn trusted_ancestors(path: &Path) -> bool {
        if !path.is_absolute() {
            return false;
        }
        let mut current = PathBuf::from("/");
        for part in path.components() {
            match part {
                Component::RootDir => (),
                Component::Normal(name) => current.push(name),
                _ => return false,
            }
            let Ok(meta) = std::fs::symlink_metadata(&current) else {
                return false;
            };
            if !meta.file_type().is_dir() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
                return false;
            }
        }
        true
    }
    pub fn run() -> Result<(), &'static str> {
        if unsafe { libc::geteuid() } != 0 {
            return Err("续期程序需要 root 权限");
        }
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0
            || unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0
        {
            return Err("无法保护进程");
        }
        unsafe {
            libc::umask(0o077);
        }
        let args = arguments()?;
        if !args.target.is_absolute()
            || !trusted_ancestors(&args.root)
            || !args.target.parent().is_some_and(trusted_ancestors)
        {
            return Err("证书路径不可信");
        }
        let renewed = std::env::var_os("RENEWED_LINEAGE")
            .map(PathBuf::from)
            .ok_or("缺少续期范围")?;
        if !matches_lineage(&args.root, &args.lineage, Some(&renewed))
            .map_err(|_| "续期范围无效")?
        {
            return Ok(());
        }
        let pair = read_pair(&args.root, &args.lineage).map_err(|_| "证书来源不可用")?;
        publish_dropped(
            &args.target,
            &args.domain,
            pair.certificate(),
            pair.private_key(),
            args.uid,
            args.gid,
            args.output_gid,
        )
        .map_err(|error| match error {
            PublishError::Invalid => "证书与域名或私钥不匹配",
            PublishError::Unavailable => "证书发布不可用",
            PublishError::Uncertain => "证书发布结果未知，请核对实际文件和握手",
        })?;
        println!("证书文件已更新；仍需核对服务使用的证书。");
        Ok(())
    }
}
#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = linux::run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("此实验程序仅支持 Linux");
    std::process::exit(1);
}
