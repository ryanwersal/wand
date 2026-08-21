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
fn vulnerability_filters_are_discoverable_without_credentials() {
    let output = isolated_command()
        .args(["vulnerabilities", "filters"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output).unwrap();
    assert!(value["meta"]["count"].as_u64().unwrap() > 70);
    let filters = value["data"].as_array().unwrap();
    let repository = filters
        .iter()
        .find(|filter| filter["flag"] == "--container-repository")
        .unwrap();
    assert_eq!(repository["graphql_field"], "containerRepository");
    let cve = filters
        .iter()
        .find(|filter| filter["flag"] == "--cve")
        .unwrap();
    assert_eq!(cve["graphql_field"], "vulnerabilityExternalIdV2");
    assert_eq!(cve["operation"], "equals");
    let fixed_version = filters
        .iter()
        .find(|filter| filter["flag"] == "--fixed-version")
        .unwrap();
    assert_eq!(fixed_version["graphql_field"], "fixedVersion");
    assert_eq!(fixed_version["operation"], "equals");
    let status = filters
        .iter()
        .find(|filter| filter["flag"] == "--status")
        .unwrap();
    assert!(
        status["possible_values"]
            .as_array()
            .unwrap()
            .contains(&json!("OPEN"))
    );
    assert!(
        filters
            .iter()
            .all(|filter| filter["description"].is_string())
    );
}

#[test]
fn issue_filters_are_discoverable_without_credentials() {
    let output = isolated_command()
        .args(["issues", "filters"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output).unwrap();
    assert!(value["meta"]["count"].as_u64().unwrap() > 30);
    let filters = value["data"].as_array().unwrap();
    assert!(
        filters
            .iter()
            .any(|filter| filter["flag"] == "--has-remediation")
    );
    let security_subcategory = filters
        .iter()
        .find(|filter| filter["flag"] == "--security-subcategory")
        .unwrap();
    assert_eq!(security_subcategory["graphql_field"], "securitySubCategory");
}

#[test]
fn filter_discovery_can_search_and_render_as_a_table() {
    isolated_command()
        .args([
            "--output",
            "table",
            "vulnerabilities",
            "filters",
            "container",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("FLAG"))
        .stdout(predicate::str::contains("CATEGORY"))
        .stdout(predicate::str::contains("--container-repository"))
        .stdout(predicate::str::contains("--cve").not());
}

#[test]
fn empty_filter_discovery_table_is_explanatory() {
    isolated_command()
        .args([
            "--output",
            "table",
            "issues",
            "filters",
            "definitely-no-such-filter",
        ])
        .assert()
        .success()
        .stdout(predicate::eq(
            "No filters matched \"definitely-no-such-filter\".\n",
        ));
}

#[test]
fn list_help_groups_filters_and_points_to_searchable_discovery() {
    isolated_command()
        .args(["vulnerabilities", "list", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Container and Kubernetes:"))
        .stdout(predicate::str::contains("Severity and score:"))
        .stdout(predicate::str::contains(
            "wand vulnerabilities filters [QUERY]",
        ));
    isolated_command()
        .args(["issues", "list", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("issues filters remediation"))
        .stdout(predicate::str::contains("issues filters container").not());
}

#[test]
fn invalid_filter_values_fail_before_credentials_or_network() {
    isolated_command()
        .args(["vulnerabilities", "list", "--updated-after", "yesterday"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("RFC 3339"))
        .stderr(predicate::str::contains("WIZ_API_ENDPOINT").not());
    isolated_command()
        .args(["vulnerabilities", "list", "--min-score", "11"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("0 through 10"));
    isolated_command()
        .args([
            "vulnerabilities",
            "list",
            "--min-score",
            "9",
            "--max-score",
            "7",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "--min-score must be less than --max-score",
        ))
        .stderr(predicate::str::contains("WIZ_API_ENDPOINT").not());
    isolated_command()
        .args(["issues", "list", "--filter", "not-json"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("WIZ_API_ENDPOINT").not());
    isolated_command()
        .args(["vulnerabilities", "list", "--status", "opne"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("invalid value"))
        .stderr(predicate::str::contains("OPEN"));
    isolated_command()
        .args(["issues", "list", "--project", "prismatic"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("expects a project UUID"))
        .stderr(predicate::str::contains("WIZ_API_ENDPOINT").not());
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
async fn named_issue_filters_map_to_wiz_filter_fields() {
    let server = server().await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .and(body_partial_json(json!({"variables":{"filterBy":{
            "search":"datadog",
            "project":["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"],
            "hasRemediation":true,
            "riskEqualsAny":["internet-exposed"],
            "createdAt":{"after":"2026-01-01T00:00:00Z"}
        }}})))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data":{"page":{
                "nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}
            }}})),
        )
        .mount(&server)
        .await;
    command(&server)
        .args([
            "issues",
            "list",
            "--search",
            "datadog",
            "--project",
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "--has-remediation",
            "true",
            "--risk-any",
            "internet-exposed",
            "--created-after",
            "2026-01-01T00:00:00Z",
        ])
        .assert()
        .success();
}

#[tokio::test]
async fn named_vulnerability_filters_map_nested_lists_ranges_and_booleans() {
    let server = server().await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .and(body_string_contains("repository { name }"))
        .and(body_string_contains("registry { name }"))
        .and(body_partial_json(json!({"variables":{"filterBy":{
            "containerRepository":["11111111-2222-3333-4444-555555555555"],
            "containerRegistry":["99999999-8888-7777-6666-555555555555"],
            "vulnerabilityExternalIdV2":{"equals":["CVE-2026-1234"]},
            "projectIdV2":{"equals":["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"]},
            "assetRegion":{"equals":["us-east-1"]},
            "hasCisaKevExploit":false,
            "score":{"greaterThan":7.0,"lessThan":9.5},
            "updatedAt":{"after":"2026-01-01T00:00:00Z","before":"2026-02-01T00:00:00Z"}
        }}})))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data":{"page":{
                "nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}
            }}})),
        )
        .mount(&server)
        .await;
    command(&server)
        .args([
            "vulnerabilities",
            "list",
            "--container-repository",
            "11111111-2222-3333-4444-555555555555",
            "--container-registry",
            "99999999-8888-7777-6666-555555555555",
            "--cve",
            "CVE-2026-1234",
            "--project",
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "--region",
            "us-east-1",
            "--has-cisa-kev-exploit",
            "false",
            "--min-score",
            "7",
            "--max-score",
            "9.5",
            "--updated-after",
            "2026-01-01T00:00:00Z",
            "--updated-before",
            "2026-02-01T00:00:00Z",
        ])
        .assert()
        .success();
}

#[tokio::test]
async fn container_repository_names_are_resolved_to_wiz_ids() {
    let server = server().await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .and(body_partial_json(json!({
            "operationName":"ContainerRepositoriesByName",
            "variables":{"search":"datadog/agent"}
        })))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data":{"page":{"nodes":[{
                "id":"11111111-2222-3333-4444-555555555555",
                "externalId":"public.ecr.aws/datadog/agent",
                "name":"datadog/agent",
                "shortName":"agent",
                "registry":{"name":"public.ecr.aws"}
            }]}}})),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .and(body_partial_json(json!({"variables":{"filterBy":{
            "containerRepository":["11111111-2222-3333-4444-555555555555"]
        }}})))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data":{"page":{
                "nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}
            }}})),
        )
        .mount(&server)
        .await;
    command(&server)
        .args([
            "vulnerabilities",
            "list",
            "--container-repository",
            "datadog/agent",
        ])
        .assert()
        .success();
}

#[tokio::test]
async fn repository_lookup_never_accepts_a_single_fuzzy_result() {
    let server = server().await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data":{"page":{
                "nodes":[{
                    "id":"11111111-2222-3333-4444-555555555555",
                    "externalId":"registry.example.com/some-other-agent",
                    "name":"some-other-agent",
                    "shortName":"some-other-agent",
                    "registry":{"name":"registry.example.com"}
                }],
                "pageInfo":{"hasNextPage":false}
            }}})),
        )
        .mount(&server)
        .await;
    command(&server)
        .args([
            "vulnerabilities",
            "list",
            "--container-repository",
            "datadog/agnet",
        ])
        .assert()
        .code(4)
        .stderr(predicate::str::contains("no container repository matched"));
}

#[tokio::test]
async fn truncated_name_lookup_fails_instead_of_hiding_candidates() {
    let server = server().await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data":{"page":{
                "nodes":[],"pageInfo":{"hasNextPage":true}
            }}})),
        )
        .mount(&server)
        .await;
    command(&server)
        .args(["vulnerabilities", "list", "--container-repository", "agent"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("more than 100 candidates"))
        .stderr(predicate::str::contains("pass the Wiz UUID"));
}

#[tokio::test]
async fn container_registry_names_are_resolved_to_wiz_ids() {
    let server = server().await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .and(body_partial_json(json!({
            "operationName":"ContainerRegistriesByName",
            "variables":{"search":"public.ecr.aws"}
        })))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data":{"page":{"nodes":[{
                "id":"99999999-8888-7777-6666-555555555555",
                "name":"public.ecr.aws",
                "externalId":"public.ecr.aws"
            }]}}})),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .and(body_partial_json(json!({"variables":{"filterBy":{
            "containerRegistry":["99999999-8888-7777-6666-555555555555"]
        }}})))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data":{"page":{
                "nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}
            }}})),
        )
        .mount(&server)
        .await;
    command(&server)
        .args([
            "vulnerabilities",
            "list",
            "--container-registry",
            "public.ecr.aws",
        ])
        .assert()
        .success();
}

#[tokio::test]
async fn base_container_image_names_are_resolved_to_wiz_ids() {
    let server = server().await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .and(body_partial_json(json!({
            "operationName":"ContainerImagesByName",
            "variables":{"search":"ubuntu:24.04"}
        })))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data":{"page":{"nodes":[{
                "id":"12121212-3434-5656-7878-909090909090",
                "name":"ubuntu:24.04",
                "shortName":"ubuntu:24.04",
                "digest":"sha256:abc"
            }]}}})),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .and(body_partial_json(json!({"variables":{"filterBy":{
            "baseContainerImage":["12121212-3434-5656-7878-909090909090"]
        }}})))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data":{"page":{
                "nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}
            }}})),
        )
        .mount(&server)
        .await;
    command(&server)
        .args([
            "vulnerabilities",
            "list",
            "--base-container-image",
            "ubuntu:24.04",
        ])
        .assert()
        .success();
}

#[tokio::test]
async fn base_image_lookup_never_accepts_a_single_fuzzy_result() {
    let server = server().await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data":{"page":{
                "nodes":[{
                    "id":"12121212-3434-5656-7878-909090909090",
                    "name":"ubuntu:22.04",
                    "shortName":"ubuntu:22.04",
                    "digest":"sha256:abc"
                }],
                "pageInfo":{"hasNextPage":false}
            }}})),
        )
        .mount(&server)
        .await;
    command(&server)
        .args([
            "vulnerabilities",
            "list",
            "--base-container-image",
            "ubuntu:24.40",
        ])
        .assert()
        .code(4)
        .stderr(predicate::str::contains("no container image matched"));
}

#[tokio::test]
async fn multi_value_filters_are_trimmed_deduplicated_and_normalized() {
    let server = server().await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .and(body_partial_json(json!({"variables":{"filterBy":{
            "severity":["CRITICAL","HIGH"],
            "containerRepository":["11111111-2222-3333-4444-555555555555"]
        }}})))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data":{"page":{
                "nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}
            }}})),
        )
        .mount(&server)
        .await;
    command(&server)
        .args([
            "vulnerabilities",
            "list",
            "--severity",
            "critical, high,critical",
            "--container-repository",
            "11111111-2222-3333-4444-555555555555,11111111-2222-3333-4444-555555555555",
        ])
        .assert()
        .success();
}

#[tokio::test]
async fn named_range_bounds_merge_with_advanced_filter_siblings() {
    let server = server().await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .and(body_partial_json(json!({"variables":{"filterBy":{
            "score":{"greaterThan":7.0,"lessThan":10},
            "updatedAt":{"after":"2026-01-01T00:00:00Z","before":"2026-02-01T00:00:00Z"}
        }}})))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data":{"page":{
                "nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}
            }}})),
        )
        .mount(&server)
        .await;
    command(&server)
        .args([
            "vulnerabilities",
            "list",
            "--filter",
            r#"{"score":{"lessThan":10},"updatedAt":{"before":"2026-02-01T00:00:00Z"}}"#,
            "--min-score",
            "7",
            "--updated-after",
            "2026-01-01T00:00:00Z",
        ])
        .assert()
        .success();
}

#[tokio::test]
async fn vulnerability_project_names_are_resolved_and_boolean_flags_default_true() {
    let server = server().await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .and(body_partial_json(json!({
            "operationName":"ProjectsByName",
            "variables":{"search":"prismatic"}
        })))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data":{"page":{"nodes":[{
                "id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "name":"Prismatic",
                "slug":"prismatic",
                "archived":false
            }]}}})),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .and(body_partial_json(json!({"variables":{"filterBy":{
            "projectIdV2":{"equals":["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"]},
            "hasExploit":true,
            "hasFix":false
        }}})))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data":{"page":{
                "nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}
            }}})),
        )
        .mount(&server)
        .await;
    command(&server)
        .args([
            "vulnerabilities",
            "list",
            "--project",
            "prismatic",
            "--has-exploit",
            "--has-fix=false",
        ])
        .assert()
        .success();
}

#[tokio::test]
async fn project_name_resolution_explains_the_optional_permission() {
    let server = server().await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .and(body_partial_json(json!({"operationName":"ProjectsByName"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "errors":[{"message":"access denied, required: [read:projects]"}]
        })))
        .mount(&server)
        .await;
    command(&server)
        .args(["vulnerabilities", "list", "--project", "prismatic"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("requires read:projects"))
        .stderr(predicate::str::contains("pass the project UUID"));
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
