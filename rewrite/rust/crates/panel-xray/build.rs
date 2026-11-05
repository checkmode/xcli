use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?).join("../../../../cpp/proto");
    println!("cargo:rerun-if-changed={}", proto.display());
    let files = [
        "app/proxyman/command/command.proto",
        "app/stats/command/command.proto",
        "proxy/vless/account.proto",
        "proxy/vmess/account.proto",
        "proxy/hysteria/account/config.proto",
    ]
    .map(|name| proto.join(name));
    let mut config = prost_build::Config::new();
    config.protoc_executable(protoc_bin_vendored::protoc_bin_path()?);
    config.include_file("_includes.rs");
    tonic_prost_build::configure()
        .build_server(false)
        .compile_with_config(config, &files, &[proto])?;
    Ok(())
}
