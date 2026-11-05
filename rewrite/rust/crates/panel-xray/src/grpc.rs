use super::generated::xray::{
    app::proxyman::command::{
        handler_service_client::HandlerServiceClient, AddUserOperation, AlterInboundRequest,
        GetInboundUserRequest,
    },
    app::stats::command::{stats_service_client::StatsServiceClient, QueryStatsRequest},
    common::{protocol, serial::TypedMessage},
    proxy::{hysteria, vless, vmess},
};
use super::ProcessIdentity;
use prost::Message;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::mpsc::{self, Sender};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tonic::transport::{Channel, Endpoint};
use xcli_panel_controller::{Core, Error, User};
use xcli_panel_traffic::Counter;

type Result<T> = std::result::Result<T, Error>;
const DEADLINE: Duration = Duration::from_secs(3);
const MAX_RESPONSE: usize = 8 * 1024 * 1024;

enum Request {
    Counters(Sender<Result<Vec<Counter>>>),
    Users(String, Sender<Result<BTreeMap<String, String>>>),
    Add(String, User, Sender<Result<()>>),
    Stop,
}

fn residential(tag: &str) -> bool {
    tag.strip_prefix("residential-")
        .is_some_and(|suffix| suffix.len() == 2 && suffix.bytes().all(|c| c.is_ascii_digit()))
}
fn residential_hy2(tag: &str) -> bool {
    tag.strip_suffix("-hy2").is_some_and(residential)
}
fn valid_tag(tag: &str) -> bool {
    matches!(
        tag,
        "reality" | "websocket" | "hysteria2" | "hysteria2-brutal" | "vmess"
    ) || residential(tag)
        || residential_hy2(tag)
}
fn direct_hy2(tag: &str) -> bool {
    matches!(tag, "hysteria2" | "hysteria2-brutal")
}
fn timeout<T>(input: T) -> tonic::Request<T> {
    let mut request = tonic::Request::new(input);
    request.set_timeout(DEADLINE);
    request
}
async fn counters(client: &mut StatsServiceClient<Channel>) -> Result<Vec<Counter>> {
    let request = timeout(QueryStatsRequest {
        pattern: "user>>>".into(),
        reset: false,
    });
    let response = tokio::time::timeout(DEADLINE, client.query_stats(request))
        .await
        .map_err(|_| Error::CoreUnavailable)?
        .map_err(|_| Error::CoreUnavailable)?
        .into_inner();
    Ok(response
        .stat
        .into_iter()
        .map(|stat| Counter {
            name: stat.name,
            value: stat.value,
        })
        .collect())
}
async fn users(
    client: &mut HandlerServiceClient<Channel>,
    tag: &str,
    hy2: &BTreeSet<String>,
) -> Result<BTreeMap<String, String>> {
    let target = if hy2.contains(tag) { "hysteria2" } else { tag };
    let request = timeout(GetInboundUserRequest {
        tag: target.to_owned(),
        email: String::new(),
    });
    let response = tokio::time::timeout(DEADLINE, client.get_inbound_users(request))
        .await
        .map_err(|_| Error::CoreUnavailable)?
        .map_err(|_| Error::CoreUnavailable)?
        .into_inner();
    let mut result = BTreeMap::new();
    for user in response.users {
        let logical = user
            .email
            .rsplit_once('@')
            .map(|(_, logical)| logical)
            .unwrap_or("");
        if tag == "hysteria2" && hy2.contains(logical) {
            continue;
        }
        if hy2.contains(tag) && logical != tag {
            continue;
        }
        let account = user.account.ok_or(Error::CoreUnavailable)?;
        let value = if direct_hy2(tag) || hy2.contains(tag) {
            if account.r#type != "xray.proxy.hysteria.account.Account" {
                return Err(Error::CoreUnavailable);
            }
            let auth = hysteria::account::Account::decode(account.value.as_slice())
                .map_err(|_| Error::CoreUnavailable)?
                .auth;
            if direct_hy2(tag) {
                auth
            } else {
                auth.strip_suffix(&format!(".{tag}"))
                    .unwrap_or("invalid-auth-suffix")
                    .to_owned()
            }
        } else if tag == "vmess" {
            if account.r#type != "xray.proxy.vmess.Account" {
                return Err(Error::CoreUnavailable);
            }
            vmess::Account::decode(account.value.as_slice())
                .map_err(|_| Error::CoreUnavailable)?
                .id
        } else {
            if account.r#type != "xray.proxy.vless.Account" {
                return Err(Error::CoreUnavailable);
            }
            vless::Account::decode(account.value.as_slice())
                .map_err(|_| Error::CoreUnavailable)?
                .id
        };
        result.entry(user.email).or_insert(value);
    }
    Ok(result)
}
async fn add(
    client: &mut HandlerServiceClient<Channel>,
    tag: &str,
    user: &User,
    hy2: &BTreeSet<String>,
) -> Result<()> {
    let email = user.email(tag)?;
    let account = if direct_hy2(tag) || hy2.contains(tag) {
        let auth = if direct_hy2(tag) {
            user.uuid.clone()
        } else {
            format!("{}.{tag}", user.uuid)
        };
        TypedMessage {
            r#type: "xray.proxy.hysteria.account.Account".into(),
            value: hysteria::account::Account { auth }.encode_to_vec(),
        }
    } else if tag == "vmess" {
        TypedMessage {
            r#type: "xray.proxy.vmess.Account".into(),
            value: vmess::Account {
                id: user.uuid.clone(),
                ..Default::default()
            }
            .encode_to_vec(),
        }
    } else {
        TypedMessage {
            r#type: "xray.proxy.vless.Account".into(),
            value: vless::Account {
                id: user.uuid.clone(),
                flow: if tag == "reality" {
                    "xtls-rprx-vision".into()
                } else {
                    String::new()
                },
                ..Default::default()
            }
            .encode_to_vec(),
        }
    };
    let operation = AddUserOperation {
        user: Some(protocol::User {
            level: 0,
            email,
            account: Some(account),
        }),
    };
    let request = timeout(AlterInboundRequest {
        tag: if hy2.contains(tag) {
            "hysteria2".into()
        } else {
            tag.into()
        },
        operation: Some(TypedMessage {
            r#type: "xray.app.proxyman.command.AddUserOperation".into(),
            value: operation.encode_to_vec(),
        }),
    });
    tokio::time::timeout(DEADLINE, client.alter_inbound(request))
        .await
        .map_err(|_| Error::CoreUnavailable)?
        .map_err(|_| Error::CoreUnavailable)?;
    Ok(())
}

/// Owns a dedicated gRPC worker so synchronous controller polls never nest or
/// shut down a Tokio runtime in an async context. No credentials are logged.
pub struct ManagedCore {
    identity: ProcessIdentity,
    requests: Sender<Request>,
    worker: Option<JoinHandle<()>>,
}

impl ManagedCore {
    pub fn new(api: &str, binary: &Path, pid_file: &Path, hy2: BTreeSet<String>) -> Result<Self> {
        let address: SocketAddr = api.parse().map_err(|_| Error::InvalidState)?;
        if address.port() == 0
            || !matches!(
                address.ip(),
                IpAddr::V4(Ipv4Addr::LOCALHOST) | IpAddr::V6(Ipv6Addr::LOCALHOST)
            )
            || hy2.iter().any(|tag| !residential_hy2(tag))
        {
            return Err(Error::InvalidState);
        }
        let identity = ProcessIdentity::new(binary, pid_file)?;
        let (send, receive) = mpsc::channel();
        let (ready_send, ready_receive) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("xcli-xray-grpc".into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(value) => value,
                    Err(_) => {
                        let _ = ready_send.send(false);
                        return;
                    }
                };
                let endpoint = match Endpoint::from_shared(format!("http://{address}")) {
                    Ok(value) => value.connect_timeout(DEADLINE).timeout(DEADLINE),
                    Err(_) => {
                        let _ = ready_send.send(false);
                        return;
                    }
                };
                let channel = {
                    let _guard = runtime.enter();
                    endpoint.connect_lazy()
                };
                let mut handler = HandlerServiceClient::new(channel.clone())
                    .max_decoding_message_size(MAX_RESPONSE);
                let mut stats =
                    StatsServiceClient::new(channel).max_decoding_message_size(MAX_RESPONSE);
                if ready_send.send(true).is_err() {
                    return;
                }
                while let Ok(request) = receive.recv() {
                    match request {
                        Request::Counters(reply) => {
                            let _ = reply.send(runtime.block_on(counters(&mut stats)));
                        }
                        Request::Users(tag, reply) => {
                            let _ = reply.send(runtime.block_on(users(&mut handler, &tag, &hy2)));
                        }
                        Request::Add(tag, user, reply) => {
                            let _ =
                                reply.send(runtime.block_on(add(&mut handler, &tag, &user, &hy2)));
                        }
                        Request::Stop => break,
                    }
                }
            })
            .map_err(|_| Error::CoreUnavailable)?;
        if ready_receive.recv() != Ok(true) {
            let _ = worker.join();
            return Err(Error::CoreUnavailable);
        }
        Ok(Self {
            identity,
            requests: send,
            worker: Some(worker),
        })
    }
}
impl Core for ManagedCore {
    fn generation(&mut self) -> Result<String> {
        self.identity.generation()
    }
    fn counters(&mut self) -> Result<Vec<Counter>> {
        let (send, receive) = mpsc::channel();
        self.requests
            .send(Request::Counters(send))
            .map_err(|_| Error::CoreUnavailable)?;
        receive.recv().map_err(|_| Error::CoreUnavailable)?
    }
    fn users(&mut self, tag: &str) -> Result<BTreeMap<String, String>> {
        if !valid_tag(tag) {
            return Err(Error::InvalidState);
        }
        let (send, receive) = mpsc::channel();
        self.requests
            .send(Request::Users(tag.into(), send))
            .map_err(|_| Error::CoreUnavailable)?;
        receive.recv().map_err(|_| Error::CoreUnavailable)?
    }
    fn add(&mut self, tag: &str, user: &User) -> Result<()> {
        if !valid_tag(tag) {
            return Err(Error::InvalidState);
        }
        let (send, receive) = mpsc::channel();
        self.requests
            .send(Request::Add(tag.into(), user.clone(), send))
            .map_err(|_| Error::CoreUnavailable)?;
        receive.recv().map_err(|_| Error::CoreUnavailable)?
    }
    fn restart(&mut self, expected: &str) -> Result<()> {
        self.identity.restart(expected)
    }
}
impl Drop for ManagedCore {
    fn drop(&mut self) {
        let _ = self.requests.send(Request::Stop);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
