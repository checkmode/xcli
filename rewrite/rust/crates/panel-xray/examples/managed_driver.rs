//! Test-only driver. It must point only to a disposable loopback Xray core.
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::io::{self, BufRead};
use std::path::Path;
use xcli_panel_controller::{poll, Core, Outcome, SqliteStore, User};
use xcli_panel_xray::ManagedCore;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(
        args.len(),
        6,
        "expected test binary, pid file, API, optional hy2 tag and disposable database"
    );
    let hy2 = if args[4].is_empty() {
        BTreeSet::new()
    } else {
        BTreeSet::from([args[4].clone()])
    };
    let mut core = ManagedCore::new(&args[3], Path::new(&args[1]), Path::new(&args[2]), hy2)
        .expect("test core configuration");
    let mut store = SqliteStore::open(Path::new(&args[5]), 5, None).expect("test database");
    for line in io::stdin().lock().lines() {
        let input: Value = serde_json::from_str(&line.unwrap()).unwrap();
        let tag = input["tag"].as_str().unwrap_or("");
        let result = match input["op"].as_str() {
            Some("generation") => core.generation().map(|v| json!(v)),
            Some("users") => core.users(tag).map(|v| json!(v)),
            Some("counters") => core.counters().map(|v| {
                json!(v
                    .into_iter()
                    .map(|c| json!({"name":c.name,"value":c.value}))
                    .collect::<Vec<_>>())
            }),
            Some("add") => {
                let user = User {
                    id: input["id"].as_str().unwrap().into(),
                    uuid: input["uuid"].as_str().unwrap().into(),
                    enabled: true,
                    deleted: false,
                    quota: 0,
                    expires: 0,
                    upload: 0,
                    download: 0,
                };
                core.add(tag, &user).map(|_| json!(null))
            }
            Some("restart") => core
                .restart(input["generation"].as_str().unwrap())
                .map(|_| json!(null)),
            Some("poll") => {
                let tags = input["tags"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|value| value.as_str().unwrap().to_owned())
                    .collect::<Vec<_>>();
                poll(&mut core, &mut store, &tags, input["now"].as_i64().unwrap()).map(|value| {
                    match value {
                        Outcome::Ready { added } => json!({"state":"ready","added":added}),
                        Outcome::Restarting => json!({"state":"restarting"}),
                    }
                })
            }
            _ => panic!("unknown test operation"),
        };
        println!(
            "{}",
            match result {
                Ok(value) => json!({"ok":true,"value":value}),
                Err(error) => json!({"ok":false,"error":format!("{error:?}")}),
            }
        );
    }
}
