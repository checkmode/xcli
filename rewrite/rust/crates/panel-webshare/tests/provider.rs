use serde_json::json;
use xcli_panel_webshare::provider::{credentials, plans, session_username, usage, ProviderError};

#[test]
fn accepts_only_active_residential_plans_and_filters_sensitive_usage() {
    let result=plans(&json!({"results":[{"id":17,"status":"active","pool_filter":"residential","bandwidth_limit":10},
        {"id":18,"status":"active","proxy_subtype":"isp"},{"id":19,"status":"cancelled","pool_filter":"residential"},
        {"id":"bad","status":"active"},{"status":"active"}]})).unwrap();
    assert_eq!(result.len(), 3);
    assert_eq!(result[0]["eligible"], true);
    assert_eq!(result[1]["eligible"], false);
    assert_eq!(result[2]["eligible"], false);
    assert_eq!(
        plans(&json!({"results":{}})),
        Err(ProviderError::InvalidPlanData)
    );
    assert_eq!(
        plans(&json!({ "results": vec![json!({"id":1}); 1001] })),
        Err(ProviderError::InvalidPlanData)
    );
    let usage = usage(
        &json!({"bandwidth_total":1234,"requests_total":10,"requests_successful":9,"requests_failed":-1,"secret":"hidden"}),
    );
    assert_eq!(
        usage,
        json!({"bandwidth_total":1234,"requests_total":10,"requests_successful":9})
    );
}

#[test]
fn validates_credentials_and_session_names_without_echoing_them() {
    let credential = credentials(
        &json!({"results":[{"username":"testuser001-1234","password":"synthetic-password"}]}),
    )
    .unwrap();
    assert_eq!(credential.base.as_str(), "testuser001");
    assert_eq!(credential.password.as_str(), "synthetic-password");
    assert_eq!(
        session_username(&credential.base, "US", "1234")
            .unwrap()
            .as_str(),
        "testuser001-us-1234"
    );
    assert_eq!(
        session_username(&credential.base, "ZZ", "1234")
            .unwrap()
            .as_str(),
        "testuser001-1234"
    );
    assert!(session_username(&credential.base, "XX", "1234").is_err());
    assert!(session_username(&credential.base, "US", "-1").is_err());
    for username in ["-bad", "bad-", "bad space", "bad!user", ""] {
        assert!(matches!(
            credentials(&json!({"results":[{"username":username,"password":"synthetic"}]})),
            Err(ProviderError::InvalidUsername)
        ));
    }
    assert!(matches!(
        credentials(&json!({"results":[]})),
        Err(ProviderError::NoCredentials)
    ));
    assert!(matches!(
        credentials(&json!({"results":[{"username":"fixture","password":"\n"}]})),
        Err(ProviderError::InvalidPassword)
    ));
}
