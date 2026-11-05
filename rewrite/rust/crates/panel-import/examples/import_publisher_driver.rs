//! Disposable crash-test driver; never use with production paths or credentials.
use serde_json::json;
use std::io::Write;
use std::path::Path;
use std::time::Duration;
use xcli_panel_import::publisher::{
    audit::SqliteAuditor, AuditRecord, Auditor, PublishError, Publisher,
};

struct PauseAfterWrite {
    after_audit: bool,
    auditor: SqliteAuditor,
}
impl Auditor for PauseAfterWrite {
    fn record(&mut self, record: &AuditRecord) -> Result<(), PublishError> {
        if self.after_audit {
            self.auditor.record(record)?;
        }
        println!("ready");
        std::io::stdout()
            .flush()
            .map_err(|_| PublishError::Unavailable)?;
        loop {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
}
fn main() {
    let mut args = std::env::args().skip(1);
    let mode = args.next().expect("mode");
    let inbox = args.next().expect("inbox");
    let database = args.next().expect("database");
    assert!(args.next().is_none());
    let key = [42u8; 32];
    let publisher = Publisher::open(Path::new(&inbox), key).expect("fixture publisher");
    let auditor = SqliteAuditor::open(Path::new(&database)).expect("fixture auditor");
    match mode.as_str() {
        "before" | "after" => {
            let request = xcli_panel_import::request::prepare(
                &json!({"action":"preview","protocol":"socks","label":"fixture",
                "text":"1.1.1.1:80:synthetic-user:synthetic-password"}),
                1000,
                &key,
                0,
            )
            .expect("fixture request");
            let mut auditor = PauseAfterWrite {
                after_audit: mode == "after",
                auditor,
            };
            publisher
                .submit(
                    &request,
                    &json!({"status":"idle","updated":1000,"id":""}),
                    1000,
                    &mut auditor,
                )
                .expect("fixture publication");
        }
        "recover" => {
            let mut auditor = auditor;
            publisher
                .recover(1000, &mut auditor)
                .expect("fixture recovery");
            publisher
                .recover(1000, &mut auditor)
                .expect("fixture repeat recovery");
            println!("recovered");
        }
        _ => panic!("unsupported fixture mode"),
    }
}
