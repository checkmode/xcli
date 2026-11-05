//! Synthetic compatibility fixture. Never provide real proxy credentials.
use serde_json::{json, Value};
use std::io::{self, BufRead};
use xcli_panel_import::config::{
    add_fixed, add_vmess, enable_all_residential_hysteria, enable_residential_hysteria,
    enable_vmess, manage, Files, Manage, Verified, VerifiedVmess,
};
use xcli_panel_import::parse_fixed;
use xcli_panel_import::probe::{ProbeResult, Protocol};
use xcli_panel_import::vmess::parse_links;
use xcli_panel_import::vmess_probe::VmessProbeResult;

fn candidate(value: Value) -> Result<Value, ()> {
    let files = &value["files"];
    let locations = files
        .get("locations")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let pool = files.get("pool").filter(|value| !value.is_null()).cloned();
    let files = Files::new(
        files["settings"].clone(),
        files["core"].clone(),
        files["monitor"].clone(),
        files["nginx"].as_str().ok_or(())?.into(),
        locations,
        pool,
    )
    .map_err(|_| ())?;
    if let Some(operation) = value["operation"].as_str() {
        if operation == "enable-vmess" {
            let (files, entries) = enable_vmess(files).map_err(|_| ())?;
            return Ok(
                json!({"ok":true,"settings":files.settings(),"core":files.core(),"monitor":files.monitor(),
                "pool":files.pool(),"nginx":files.nginx(),"locations":files.locations(),"entries":entries}),
            );
        }
        if operation == "enable-hysteria" || operation == "enable-all-hysteria" {
            let (files, entries) = if operation == "enable-hysteria" {
                enable_residential_hysteria(files, value["tag"].as_str().ok_or(())?)
            } else {
                enable_all_residential_hysteria(files)
            }
            .map_err(|_| ())?;
            return Ok(
                json!({"ok":true,"settings":files.settings(),"core":files.core(),"monitor":files.monitor(),
                "pool":files.pool(),"nginx":files.nginx(),"locations":files.locations(),"entries":entries}),
            );
        }
        let tag = value["tag"].as_str().ok_or(())?;
        let verified = &value["verified"];
        let result = if operation == "enable" || operation == "edit" {
            Some(ProbeResult {
                exit_ip: verified["exit_ip"]
                    .as_str()
                    .ok_or(())?
                    .parse()
                    .map_err(|_| ())?,
                country: verified["country"].as_str().ok_or(())?.into(),
                https_ms: 1,
                doh_ms: 1,
            })
        } else {
            None
        };
        let action = match operation {
            "disable" => Manage::Disable,
            "delete" => Manage::Delete {
                now: value["now"].as_u64().ok_or(())?,
            },
            "restore" => Manage::Restore,
            "enable" => Manage::Enable {
                result: result.as_ref().ok_or(())?,
                server_ip: verified
                    .get("server_ip")
                    .and_then(Value::as_str)
                    .map(|value| value.parse().map_err(|_| ()))
                    .transpose()?,
            },
            "edit" => Manage::Edit {
                changes: &value["changes"],
                result: result.as_ref().ok_or(())?,
                server_ip: verified
                    .get("server_ip")
                    .and_then(Value::as_str)
                    .map(|value| value.parse().map_err(|_| ()))
                    .transpose()?,
            },
            _ => return Err(()),
        };
        let (files, entries) = manage(files, tag, action).map_err(|_| ())?;
        return Ok(
            json!({"ok":true,"settings":files.settings(),"core":files.core(),"monitor":files.monitor(),
            "pool":files.pool(),"nginx":files.nginx(),"locations":files.locations(),"entries":entries}),
        );
    }
    let inputs = value["inputs"].as_array().ok_or(())?;
    let label = value["label"].as_str().ok_or(())?;
    if inputs.first().and_then(|input| input["protocol"].as_str()) == Some("vmess") {
        let mut proxies = Vec::new();
        let mut results = Vec::new();
        for input in inputs {
            let mut parsed = parse_links(input["link"].as_str().ok_or(())?).map_err(|_| ())?;
            if parsed.len() != 1 {
                return Err(());
            }
            proxies.push(parsed.remove(0));
            results.push(VmessProbeResult {
                server_ip: input["server_ip"]
                    .as_str()
                    .ok_or(())?
                    .parse()
                    .map_err(|_| ())?,
                observed: ProbeResult {
                    exit_ip: input["exit_ip"]
                        .as_str()
                        .ok_or(())?
                        .parse()
                        .map_err(|_| ())?,
                    country: input["country"].as_str().ok_or(())?.into(),
                    https_ms: 1,
                    doh_ms: 1,
                },
            });
        }
        let rows: Vec<_> = (0..proxies.len())
            .map(|index| VerifiedVmess {
                proxy: &proxies[index],
                result: &results[index],
            })
            .collect();
        let (files, entries) = add_vmess(files, &rows, label).map_err(|_| ())?;
        return Ok(
            json!({"ok":true,"settings":files.settings(),"core":files.core(),"monitor":files.monitor(),
            "pool":files.pool(),"nginx":files.nginx(),"locations":files.locations(),"entries":entries}),
        );
    }
    let mut proxies = Vec::new();
    let mut protocols = Vec::new();
    let mut results = Vec::new();
    for input in inputs {
        let text = format!(
            "{}:{}:{}:{}",
            input["address"].as_str().ok_or(())?,
            input["port"].as_u64().ok_or(())?,
            input["username"].as_str().ok_or(())?,
            input["password"].as_str().ok_or(())?
        );
        let mut parsed = parse_fixed(&text).map_err(|_| ())?;
        proxies.push(parsed.remove(0));
        protocols.push(match input["protocol"].as_str() {
            Some("socks") => Protocol::Socks,
            Some("http") => Protocol::Http,
            _ => return Err(()),
        });
        results.push(ProbeResult {
            exit_ip: input["exit_ip"]
                .as_str()
                .ok_or(())?
                .parse()
                .map_err(|_| ())?,
            country: input["country"].as_str().ok_or(())?.into(),
            https_ms: 1,
            doh_ms: 1,
        });
    }
    let rows: Vec<_> = (0..proxies.len())
        .map(|index| Verified {
            proxy: &proxies[index],
            protocol: protocols[index],
            result: &results[index],
        })
        .collect();
    let (files, entries) = add_fixed(files, &rows, label).map_err(|_| ())?;
    Ok(
        json!({"ok":true,"settings":files.settings(),"core":files.core(),"monitor":files.monitor(),
        "pool":files.pool(),"nginx":files.nginx(),"locations":files.locations(),"entries":entries}),
    )
}
fn main() {
    for line in io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let result = serde_json::from_str::<Value>(&line)
            .map_err(|_| ())
            .and_then(candidate)
            .unwrap_or_else(|_| json!({"ok":false}));
        println!("{result}");
    }
}
