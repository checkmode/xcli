use serde_json::{json, Value};
use xcli_panel_rules::residential::{attach_registry, names, reserved_name};

fn exit(tag: &str, country: &str) -> Value {
    json!({"tag":tag, "country":country, "label":"provider", "exit_ip":"8.8.8.8"})
}

#[test]
fn country_numbers_survive_disable_restore_reorder_and_new_imports() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("panel.sqlite");
    let db = rusqlite::Connection::open(&db_path).unwrap();
    db.execute_batch("CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);")
        .unwrap();
    let mut settings = json!({"residential_exits":[exit("residential-34","SG"),
        exit("residential-32","JP"), exit("residential-33","SG")]});
    attach_registry(&db_path, &mut settings).unwrap();
    let initial = names(&settings).unwrap();
    assert_eq!(initial["residential-33"], "新加坡01");
    assert_eq!(initial["residential-34"], "新加坡02");
    assert_eq!(initial["residential-32"], "日本01");

    let mut after_disable_and_import = json!({"residential_exits":[exit("residential-34","SG"),
        exit("residential-35","SG"), exit("residential-32","JP")]});
    attach_registry(&db_path, &mut after_disable_and_import).unwrap();
    let updated = names(&after_disable_and_import).unwrap();
    assert_eq!(updated["residential-34"], "新加坡02");
    assert_eq!(updated["residential-35"], "新加坡03");
    after_disable_and_import["residential_exits"][0]["label"] = json!("updated note");
    after_disable_and_import["residential_exits"][0]["exit_ip"] = json!("9.9.9.9");
    assert_eq!(names(&after_disable_and_import).unwrap()["residential-34"], "新加坡02");
    assert_eq!(
        reserved_name(&after_disable_and_import, "residential-33", "SG").as_deref(),
        Some("新加坡01")
    );

    after_disable_and_import["residential_exits"]
        .as_array_mut()
        .unwrap()
        .push(exit("residential-33", "SG"));
    attach_registry(&db_path, &mut after_disable_and_import).unwrap();
    assert_eq!(
        names(&after_disable_and_import).unwrap()["residential-33"],
        "新加坡01"
    );
    after_disable_and_import["residential_exits"][0]["country"] = json!("JP");
    attach_registry(&db_path, &mut after_disable_and_import).unwrap();
    assert_eq!(
        names(&after_disable_and_import).unwrap()["residential-34"],
        "日本02"
    );
    after_disable_and_import["residential_exits"][0]["country"] = json!("SG");
    attach_registry(&db_path, &mut after_disable_and_import).unwrap();
    assert_eq!(
        names(&after_disable_and_import).unwrap()["residential-34"],
        "新加坡02"
    );
    let mut disabled = json!({"residential_exits":[]});
    attach_registry(&db_path, &mut disabled).unwrap();
    assert_eq!(
        reserved_name(&disabled, "residential-33", "SG").as_deref(),
        Some("新加坡01")
    );
}

#[test]
fn standalone_names_are_deterministic_and_dynamic_labels_are_not_renumbered() {
    let settings = json!({"residential_exits":[exit("residential-42","SG"),
        {"tag":"residential-11","country":"SG","label":"动态新加坡","dynamic":true},
        exit("residential-33","SG")]});
    let names = names(&settings).unwrap();
    assert_eq!(names["residential-33"], "新加坡01");
    assert_eq!(names["residential-42"], "新加坡02");
    assert!(!names.contains_key("residential-11"));
}
