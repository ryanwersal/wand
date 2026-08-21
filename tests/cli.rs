use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use serde_json::{Value, json};
use std::net::TcpListener;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, body_string_contains, header, method, path},
};

async fn server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(header("content-type", "application/x-www-form-urlencoded"))
        .and(body_string_contains("grant_type=client_credentials"))
        .and(body_string_contains("client_id=test-client"))
        .and(body_string_contains("client_secret=super-secret"))
        .and(body_string_contains("audience=wiz-api"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token":"test-token","expires_in":3600
        })))
        .mount(&server)
        .await;
    server
}

fn isolated_command() -> assert_cmd::Command {
    let mut command = cargo_bin_cmd!("wand");
    for name in [
        "WIZ_API_ENDPOINT",
        "WIZ_AUTH_ENDPOINT",
        "WIZ_AUDIENCE",
        "WIZ_CLIENT_ID",
        "WIZ_CLIENT_SECRET",
        "WAND_TIMEOUT",
        "WAND_RETRIES",
        "WAND_MAX_RESPONSE_BYTES",
        "WAND_ALLOW_INSECURE_HTTP",
    ] {
        command.env_remove(name);
    }
    command
}

fn command(server: &MockServer) -> assert_cmd::Command {
    let mut command = isolated_command();
    command.args([
        "--endpoint",
        &format!("{}/graphql", server.uri()),
        "--auth-endpoint",
        &format!("{}/oauth/token", server.uri()),
        "--client-id",
        "test-client",
        "--allow-insecure-http",
    ]);
    command
        .env("WIZ_CLIENT_SECRET", "super-secret")
        .env("WAND_RETRIES", "0");
    command
}

#[test]
fn agent_schema_is_local_and_machine_readable() {
    let output = isolated_command()
        .args(["agent", "schema"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["schema_version"], "1");
    assert_eq!(value["data"]["read_only"], true);
    assert!(value["data"]["commands"].as_array().unwrap().len() >= 7);
}

#[test]
fn missing_configuration_has_stable_error_and_exit() {
    isolated_command()
        .args(["auth", "check"])
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("configuration_error"))
        .stderr(predicate::str::contains("WIZ_API_ENDPOINT is required"));
}

#[test]
fn insecure_endpoints_are_rejected_without_opt_in() {
    isolated_command()
        .args([
            "--endpoint",
            "http://127.0.0.1/graphql",
            "--client-id",
            "id",
            "auth",
            "check",
        ])
        .env("WIZ_CLIENT_SECRET", "secret")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("must use HTTPS"));
}

#[test]
fn insecure_opt_in_is_still_restricted_to_loopback() {
    isolated_command()
        .args([
            "--endpoint",
            "http://example.com/graphql",
            "--client-id",
            "id",
            "--allow-insecure-http",
            "auth",
            "check",
        ])
        .env("WIZ_CLIENT_SECRET", "secret")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("restricted to loopback hosts"));
}

#[test]
fn insecure_opt_in_rejects_non_http_schemes() {
    isolated_command()
        .args([
            "--endpoint",
            "ftp://localhost/graphql",
            "--client-id",
            "id",
            "--allow-insecure-http",
            "auth",
            "check",
        ])
        .env("WIZ_CLIENT_SECRET", "secret")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("must use HTTPS"));
}

#[test]
fn raw_mutations_are_rejected_before_configuration_or_network_access() {
    isolated_command()
        .args([
            "api",
            "graphql",
            "--query",
            "query Safe { viewer { id } } mutation Bad { deleteAll }",
            "--operation-name",
            "Safe",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("read-only"))
        .stderr(predicate::str::contains("WIZ_API_ENDPOINT").not());
}

#[test]
fn completions_are_generated_without_credentials() {
    isolated_command()
        .args(["completions", "bash"])
        .assert()
        .success()
        .stdout(predicate::str::contains("wand"));
}

#[test]
fn help_hides_environment_values() {
    isolated_command()
        .args(["auth", "check", "--help"])
        .env(
            "WIZ_API_ENDPOINT",
            "https://sentinel-tenant.api.app.wiz.io/graphql",
        )
        .env(
            "WIZ_AUTH_ENDPOINT",
            "https://sentinel-auth.app.wiz.io/token",
        )
        .env("WIZ_AUDIENCE", "sentinel-audience")
        .env("WIZ_CLIENT_ID", "sentinel-client-id")
        .assert()
        .success()
        .stdout(predicate::str::contains("WIZ_API_ENDPOINT"))
        .stdout(predicate::str::contains("sentinel").not());
}

#[test]
fn transport_errors_do_not_reveal_endpoint_urls() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let uri = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);

    isolated_command()
        .args([
            "--endpoint",
            &format!("{uri}/sentinel-graphql-path"),
            "--auth-endpoint",
            &format!("{uri}/sentinel-auth-path"),
            "--client-id",
            "test-client",
            "--allow-insecure-http",
            "--retries",
            "0",
            "auth",
            "check",
        ])
        .env("WIZ_CLIENT_SECRET", "test-secret")
        .assert()
        .code(5)
        .stderr(predicate::str::contains("connection failed"))
        .stderr(predicate::str::contains("sentinel").not())
        .stderr(predicate::str::contains(&uri).not());
}

#[test]
fn yaml_errors_follow_the_selected_format() {
    isolated_command()
        .args(["--output", "yaml", "auth", "check"])
        .assert()
        .code(2)
        .stderr(predicate::str::starts_with("schema_version: '1'"))
        .stderr(predicate::str::contains("code: configuration_error"));
}

#[test]
fn syntax_errors_are_structured() {
    isolated_command()
        .args(["issues", "list", "--limit", "0"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("invalid_input"));
    isolated_command()
        .args(["--output", "yaml", "issues", "list", "--limit", "0"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("code: invalid_input"));
    isolated_command()
        .args(["--output=yaml", "issues", "list", "--limit", "0"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("code: invalid_input"));
}

#[tokio::test]
async fn auth_check_validates_graphql_access() {
    let server = server().await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .and(header("authorization", "Bearer test-token"))
        .and(body_partial_json(json!({"operationName":"WandAuthCheck"})))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data":{"__typename":"Query"}})),
        )
        .mount(&server)
        .await;

    command(&server)
        .args(["auth", "check"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"graphql_access\": true"));
}

#[tokio::test]
async fn issues_list_follows_cursors_and_stops_at_limit() {
    let server = server().await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .and(body_partial_json(
            json!({"variables":{"after":null,"first":2}}),
        ))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data":{"page":{
                "nodes":[{"id":"one"},{"id":"two"}],
                "pageInfo":{"hasNextPage":true,"endCursor":"cursor-2"}
            }}})),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .and(body_partial_json(
            json!({"variables":{"after":"cursor-2","first":1}}),
        ))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data":{"page":{
                "nodes":[{"id":"three"}],
                "pageInfo":{"hasNextPage":true,"endCursor":"cursor-3"}
            }}})),
        )
        .mount(&server)
        .await;

    let output = command(&server)
        .args([
            "issues",
            "list",
            "--limit",
            "3",
            "--page-size",
            "2",
            "--severity",
            "critical,high",
            "--status",
            "open",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["data"].as_array().unwrap().len(), 3);
    assert_eq!(value["meta"]["requests"], 2);
    assert_eq!(value["meta"]["truncated"], true);
    assert_eq!(value["meta"]["next_cursor"], "cursor-3");
    assert_eq!(
        value["meta"]["filter"]["severity"],
        json!(["CRITICAL", "HIGH"])
    );
}

#[tokio::test]
async fn pagination_rejects_a_non_advancing_cursor() {
    let server = server().await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data":{"page":{
                "nodes":[{"id":"one"}],"pageInfo":{"hasNextPage":true,"endCursor":"same"}
            }}})),
        )
        .mount(&server)
        .await;
    command(&server)
        .args(["issues", "list", "--limit", "3", "--cursor", "same"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("pagination cursor repeated"));
}

#[tokio::test]
async fn graphql_errors_are_structured_and_secrets_are_redacted() {
    let server = server().await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "errors":[{
                "message":"field is unavailable for test-token and super-secret",
                "path":["sentinel-internal-path"],
                "extensions":{"debug":"super-secret"}
            }]
        })))
        .mount(&server)
        .await;
    command(&server)
        .args(["issues", "list"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("graphql_error"))
        .stderr(predicate::str::contains("field is unavailable"))
        .stderr(predicate::str::contains("[REDACTED]"))
        .stderr(predicate::str::contains("test-token").not())
        .stderr(predicate::str::contains("sentinel-internal-path").not())
        .stderr(predicate::str::contains("debug").not())
        .stderr(predicate::str::contains("super-secret").not());
}

#[tokio::test]
async fn forbidden_responses_have_a_distinct_exit_and_code() {
    let server = server().await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;
    command(&server)
        .args(["issues", "list"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("\"code\": \"forbidden\""));
}

#[tokio::test]
async fn vulnerability_get_returns_one_finding() {
    let server = server().await;
    Mock::given(method("POST")).and(path("/graphql"))
        .and(body_partial_json(json!({"variables":{"filterBy":{"id":"finding-1"},"first":1}})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data":{"page":{
            "nodes":[{"id":"finding-1","name":"TEST-VULNERABILITY-1","severity":"HIGH","status":"OPEN"}],
            "pageInfo":{"hasNextPage":false,"endCursor":null}
        }}}))).mount(&server).await;
    let output = command(&server)
        .args(["vulnerabilities", "get", "finding-1"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["data"]["id"], "finding-1");
    assert_eq!(value["meta"]["count"], 1);
}

#[tokio::test]
async fn get_rejects_a_mismatched_record() {
    let server = server().await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data":{"page":{
                "nodes":[{"id":"wrong"}],"pageInfo":{"hasNextPage":false,"endCursor":null}
            }}})),
        )
        .mount(&server)
        .await;
    command(&server)
        .args(["issues", "get", "wanted"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("returned a different record"));
}

#[tokio::test]
async fn empty_intermediate_pages_are_rejected() {
    let server = server().await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data":{"page":{
                "nodes":[],"pageInfo":{"hasNextPage":true,"endCursor":"next"}
            }}})),
        )
        .mount(&server)
        .await;
    command(&server)
        .args(["vulnerabilities", "list"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("empty page with hasNextPage=true"));
}

#[tokio::test]
async fn oversized_pages_are_rejected_instead_of_silently_skipping_records() {
    let server = server().await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data":{"page":{
                "nodes":[{"id":"one"},{"id":"two"}],
                "pageInfo":{"hasNextPage":false,"endCursor":null}
            }}})),
        )
        .mount(&server)
        .await;
    command(&server)
        .args(["issues", "list", "--limit", "1", "--page-size", "1"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "returned 2 nodes after Wand requested 1",
        ));
}

#[tokio::test]
async fn table_output_sanitizes_terminal_control_characters() {
    let server = server().await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data":{"page":{
                "nodes":[{"id":"one\n\u{1b}[31m\u{202e}spoof","severity":"HIGH"}],
                "pageInfo":{"hasNextPage":false,"endCursor":null}
            }}})),
        )
        .mount(&server)
        .await;
    command(&server)
        .args(["--output", "table", "issues", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("one  [31m"))
        .stdout(predicate::str::contains("\u{1b}").not())
        .stdout(predicate::str::contains("\u{202e}").not());
}

#[tokio::test]
async fn raw_graphql_can_preserve_partial_data() {
    let server = server().await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .and(body_partial_json(json!({"operationName":"Read"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data":{"viewer":{"id":"1"}},"errors":[{
                "message":"optional field failed",
                "extensions":{"debug":"super-secret"}
            }]
        })))
        .mount(&server)
        .await;
    let output = command(&server)
        .args([
            "api",
            "graphql",
            "--query",
            "query Read { viewer { id } }",
            "--operation-name",
            "Read",
            "--allow-partial",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["data"]["viewer"]["id"], "1");
    assert_eq!(value["meta"]["partial"], true);
    assert!(!String::from_utf8(output).unwrap().contains("super-secret"));
}

#[tokio::test]
async fn response_size_limit_is_enforced() {
    let server = server().await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(ResponseTemplate::new(200).set_body_string("x".repeat(2000)))
        .mount(&server)
        .await;
    command(&server)
        .args(["--max-response-bytes", "1024", "issues", "list"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("response exceeds 1024 byte limit"));
}

#[tokio::test]
async fn transient_graphql_failures_are_retried() {
    let server = server().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(move |_: &wiremock::Request| {
            if observed.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(503)
            } else {
                ResponseTemplate::new(200).set_body_json(json!({"data":{"page":{
                    "nodes":[{"id":"one"}],"pageInfo":{"hasNextPage":false,"endCursor":null}
                }}}))
            }
        })
        .mount(&server)
        .await;
    let mut cmd = command(&server);
    cmd.args(["--retries", "1", "issues", "list"]);
    cmd.assert().success();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}
