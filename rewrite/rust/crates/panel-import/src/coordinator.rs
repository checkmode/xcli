//! Experimental in-memory consumer for the authenticated legacy import queue.
//! It does not implement a production worker or safe service-stop hooks.
use crate::journal::{Hooks, Store};
use crate::launcher::Launcher;
use crate::preview::{self, Operation, PreviewError, Ready};
use crate::probe::Protocol;
use crate::queue::{Action, Claimed};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::Zeroizing;

enum PreviewSlot {
    Single(Ready),
    Batch(crate::batch::BatchReady),
}
#[derive(Default)]
pub struct Coordinator {
    slot: Option<(String, PreviewSlot)>,
}

fn exact(value: &Value, keys: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
    })
}

fn fixed_text(rows: &Value) -> Result<Zeroizing<String>, PreviewError> {
    let rows = rows
        .as_array()
        .filter(|rows| !rows.is_empty() && rows.len() <= 20)
        .ok_or(PreviewError::Invalid)?;
    let mut text = Zeroizing::new(String::new());
    for row in rows {
        if !exact(row, &["address", "port", "username", "password"]) {
            return Err(PreviewError::Invalid);
        }
        let address = row["address"].as_str().ok_or(PreviewError::Invalid)?;
        let port = row["port"]
            .as_u64()
            .filter(|port| (1..=65535).contains(port))
            .ok_or(PreviewError::Invalid)?;
        let username = row["username"]
            .as_str()
            .filter(|user| !user.contains(':'))
            .ok_or(PreviewError::Invalid)?;
        let password = row["password"].as_str().ok_or(PreviewError::Invalid)?;
        if [address, username, password]
            .into_iter()
            .any(|field| field.chars().any(|c| c < ' ' || c == '\u{7f}'))
        {
            return Err(PreviewError::Invalid);
        }
        use std::fmt::Write;
        writeln!(text, "{address}:{port}:{username}:{password}")
            .map_err(|_| PreviewError::Unavailable)?;
    }
    crate::parse_fixed(&text).map_err(|_| PreviewError::Invalid)?;
    Ok(text)
}

impl Coordinator {
    pub fn discard(&mut self) {
        self.slot = None;
    }
    /// A request can be consumed once by Queue. Every new preview invalidates
    /// the previous one; restart loses previews and forces re-verification.
    /// Hooks must implement journal's quiesce and counter guarantees.
    pub fn handle(
        &mut self,
        request: &Claimed,
        store: &Store,
        launcher: &Launcher,
        hooks: &mut dyn Hooks,
        now: i64,
    ) -> Result<Value, PreviewError> {
        self.handle_cancellable(request, store, launcher, hooks, now, None, None)
    }
    pub(crate) fn handle_cancellable(
        &mut self,
        request: &Claimed,
        store: &Store,
        launcher: &Launcher,
        hooks: &mut dyn Hooks,
        now: i64,
        stop: Option<&AtomicBool>,
        progress: Option<&dyn Fn(&[Value], usize) -> Result<(), PreviewError>>,
    ) -> Result<Value, PreviewError> {
        if now < 0 {
            return Err(PreviewError::Invalid);
        }
        if stop.is_some_and(|stop| stop.load(Ordering::Acquire)) {
            return Err(PreviewError::Probe);
        }
        let input = request.payload();
        match request.action() {
            Action::BrutalRate => {
                self.slot = None;
                if !exact(input, &["id", "requested_at", "action", "mbps"]) {
                    return Err(PreviewError::Invalid);
                }
                let rate = input["mbps"]
                    .as_u64()
                    .filter(|v| (1..=1000).contains(v))
                    .ok_or(PreviewError::Invalid)?;
                let (candidate, snapshot) = store.brutal_rate_candidate(rate)?;
                if let Some(candidate) = candidate {
                    store.apply(&snapshot, &candidate, hooks)?;
                }
                Ok(json!({"id":request.id(),"status":"complete"}))
            }
            Action::Preview => {
                self.slot = None;
                let protocol = input["protocol"].as_str().ok_or(PreviewError::Invalid)?;
                let label = input["label"].as_str().ok_or(PreviewError::Invalid)?;
                let ready = match protocol {
                    "socks" | "http"
                        if exact(
                            input,
                            &[
                                "id",
                                "requested_at",
                                "action",
                                "protocol",
                                "label",
                                "proxies",
                            ],
                        ) =>
                    {
                        let text = fixed_text(&input["proxies"])?;
                        preview::fixed_cancellable(
                            store,
                            launcher,
                            &text,
                            if protocol == "socks" {
                                Protocol::Socks
                            } else {
                                Protocol::Http
                            },
                            label,
                            stop,
                        )?
                    }
                    "vmess"
                        if exact(
                            input,
                            &["id", "requested_at", "action", "protocol", "label", "links"],
                        ) =>
                    {
                        preview::vmess_cancellable(
                            store,
                            launcher,
                            input["links"].as_str().ok_or(PreviewError::Invalid)?,
                            label,
                            stop,
                        )?
                    }
                    _ => return Err(PreviewError::Invalid),
                };
                Ok(self.remember(request.id(), ready))
            }
            Action::PreviewBatch => {
                self.slot = None;
                if !exact(
                    input,
                    &["id", "requested_at", "action", "protocol", "label", "text"],
                ) {
                    return Err(PreviewError::Invalid);
                }
                let noop = |_: &[Value], _: usize| Ok(());
                let batch = crate::batch::detect(
                    store,
                    launcher,
                    input["protocol"].as_str().ok_or(PreviewError::Invalid)?,
                    input["label"].as_str().ok_or(PreviewError::Invalid)?,
                    input["text"].as_str().ok_or(PreviewError::Invalid)?,
                    stop,
                    progress.unwrap_or(&noop),
                )?;
                let rows = crate::report::public_entries(batch.rows());
                let available = batch.available();
                self.slot = Some((request.id().to_owned(), PreviewSlot::Batch(batch)));
                Ok(json!({"id":request.id(),"status":"ready","rows":rows,"available":available}))
            }
            Action::Manage => {
                self.slot = None;
                let operation = input["operation"].as_str().ok_or(PreviewError::Invalid)?;
                if operation == "delete" && input.get("tags").is_some() {
                    if !exact(
                        input,
                        &["id", "requested_at", "action", "operation", "tags"],
                    ) || now <= 0
                    {
                        return Err(PreviewError::Invalid);
                    }
                    let tags = input["tags"]
                        .as_array()
                        .ok_or(PreviewError::Invalid)?
                        .iter()
                        .map(|v| v.as_str().map(str::to_owned).ok_or(PreviewError::Invalid))
                        .collect::<Result<Vec<_>, _>>()?;
                    return Ok(self.remember(
                        request.id(),
                        preview::delete_many_cancellable(store, &tags, now as u64, stop)?,
                    ));
                }
                let edit = operation == "edit";
                let valid_shape = if edit {
                    exact(
                        input,
                        &[
                            "id",
                            "requested_at",
                            "action",
                            "operation",
                            "tag",
                            "changes",
                        ],
                    )
                } else {
                    exact(input, &["id", "requested_at", "action", "operation", "tag"])
                };
                if !valid_shape {
                    return Err(PreviewError::Invalid);
                }
                let operation = match operation {
                    "disable" => Operation::Disable,
                    "delete" if now > 0 => Operation::Delete { now: now as u64 },
                    "restore" => Operation::Restore,
                    "enable" => Operation::Enable,
                    "edit" if input["changes"].is_object() => Operation::Edit {
                        changes: &input["changes"],
                    },
                    _ => return Err(PreviewError::Invalid),
                };
                let tag = input["tag"].as_str().ok_or(PreviewError::Invalid)?;
                Ok(self.remember(
                    request.id(),
                    preview::manage_cancellable(store, launcher, tag, operation, stop)?,
                ))
            }
            Action::Apply => {
                // Consume on every attempt, including invalid or mismatched IDs.
                let slot = self.slot.take().ok_or(PreviewError::Expired)?;
                if !exact(input, &["id", "requested_at", "action", "preview_id"])
                    || input["preview_id"].as_str() != Some(&slot.0)
                {
                    return Err(PreviewError::Invalid);
                }
                let PreviewSlot::Single(ready) = slot.1 else {
                    return Err(PreviewError::Invalid);
                };
                let internal_id = ready.id().to_owned();
                ready.confirm(&internal_id, store, hooks)?;
                Ok(json!({"id":request.id(),"status":"complete"}))
            }
            Action::ApplyBatch => {
                let slot = self.slot.take().ok_or(PreviewError::Expired)?;
                if !exact(
                    input,
                    &["id", "requested_at", "action", "preview_id", "selected"],
                ) || input["preview_id"].as_str() != Some(&slot.0)
                {
                    return Err(PreviewError::Invalid);
                }
                let selected = input["selected"]
                    .as_array()
                    .ok_or(PreviewError::Invalid)?
                    .iter()
                    .map(|value| {
                        value
                            .as_u64()
                            .and_then(|value| usize::try_from(value).ok())
                            .ok_or(PreviewError::Invalid)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let PreviewSlot::Batch(batch) = slot.1 else {
                    return Err(PreviewError::Invalid);
                };
                let rows = crate::report::public_entries(&batch.confirm(&selected, store, hooks)?);
                Ok(json!({"id":request.id(),"status":"complete","rows":rows}))
            }
        }
    }
    fn remember(&mut self, id: &str, ready: Ready) -> Value {
        let rows = crate::report::public_entries(ready.entries());
        self.slot = Some((id.to_owned(), PreviewSlot::Single(ready)));
        json!({"id":id,"status":"ready","rows":rows})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_injected_or_ambiguous_fixed_proxy_fields() {
        let row = json!({"address":"1.1.1.1","port":80,"username":"fixture","password":"secret:with:colon"});
        assert_eq!(
            fixed_text(&json!([row])).unwrap().as_str(),
            "1.1.1.1:80:fixture:secret:with:colon\n"
        );
        for row in [
            json!({"address":"127.0.0.1","port":80,"username":"u","password":"p"}),
            json!({"address":"1.1.1.1","port":80,"username":"u:x","password":"p"}),
            json!({"address":"1.1.1.1","port":80,"username":"u","password":"p\n8.8.8.8:80:x:y"}),
            json!({"address":"1.1.1.1","port":80,"username":"u","password":"p","unexpected":"secret"}),
        ] {
            assert!(fixed_text(&json!([row])).is_err());
        }
    }

    #[test]
    fn public_rows_never_include_arbitrary_or_nested_sensitive_fields() {
        let rows = crate::report::public_entries(&[
            json!({"tag":"residential-27","label":{"password":"synthetic-secret"},
            "username":"synthetic-user","password":"synthetic-secret","exit_ip":"8.8.8.8","port":443}),
        ]);
        let encoded = serde_json::to_string(&rows).unwrap();
        assert!(!encoded.contains("synthetic-secret"));
        assert!(!encoded.contains("synthetic-user"));
        assert_eq!(rows[0]["tag"], "residential-27");
        assert_eq!(rows[0]["port"], 443);
    }
}
