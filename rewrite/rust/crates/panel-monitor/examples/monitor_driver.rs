//! Synthetic comparison fixture; never feed real monitor credentials.
use serde_json::{json, Value};
use std::io::{self, BufRead};
use xcli_panel_monitor::{Config, SocksAuth};

fn main() {
    for line in io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let result=(|| {
            let request:Value=serde_json::from_str(&line).map_err(|_| ())?;
            let bytes=serde_json::to_vec(&request["config"]).map_err(|_| ())?;
            let config=Config::parse(&bytes).map_err(|_| ())?;
            let kind=request["kind"].as_str().ok_or(())?;
            let port=request["port"].as_u64().and_then(|value|u16::try_from(value).ok()).ok_or(())?;
            let client=if request["secure"]==true {
                config.client_secured(kind,port,&SocksAuth::random().map_err(|_| ())?).map_err(|_| ())?
            } else { config.legacy_client_for_compatibility(kind,port).map_err(|_| ())? };
            Ok::<_,()>(json!({"ok":true,"kinds":config.kinds(),"residential":config.residential(kind),"client":client.as_value()}))
        })().unwrap_or_else(|_|json!({"ok":false}));
        println!("{result}");
    }
}
