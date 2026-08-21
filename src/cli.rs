use std::{
    env, fs,
    io::{self, Read as _},
    path::PathBuf,
};

use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use clap_complete::{Shell, generate};
use serde_json::{Map, Value, json};

use crate::{
    Error, Result,
    client::WizClient,
    config::Config,
    graphql::{self, GraphqlError},
    output::{OutputFormat, envelope},
};

const ISSUES: &str = include_str!("../graphql/issues.graphql");
const VULNERABILITIES: &str = include_str!("../graphql/vulnerabilities.graphql");
const CONTAINER_REPOSITORIES: &str = r#"
query ContainerRepositoriesByName($search: String!) {
  page: containerRepositories(first: 100, filterBy: {search: $search}) {
    nodes { id externalId name shortName registry { name } }
    pageInfo { hasNextPage }
  }
}"#;
const PROJECTS: &str = r#"
query ProjectsByName($search: String!) {
  page: projects(first: 100, filterBy: {search: $search}) {
    nodes { id name slug archived }
    pageInfo { hasNextPage }
  }
}"#;
const CONTAINER_REGISTRIES: &str = r#"
query ContainerRegistriesByName($search: String!) {
  page: containerRegistries(first: 100, filterBy: {search: $search}) {
    nodes { id name externalId }
    pageInfo { hasNextPage }
  }
}"#;
const CONTAINER_IMAGES: &str = r#"
query ContainerImagesByName($search: String!) {
  page: containerImages(first: 100, filterBy: {search: $search}) {
    nodes { id name shortName digest }
    pageInfo { hasNextPage }
  }
}"#;
const AUTH_CHECK: &str = "query WandAuthCheck { __typename }";
const MAX_GRAPHQL_INPUT_BYTES: usize = 1_048_576;
const MAX_LIST_RECORDS: u32 = 10_000;
const MAX_AGGREGATE_OUTPUT_BYTES: usize = 50 * 1024 * 1024;
const MAX_GRAPHQL_ERRORS: usize = 20;
const MAX_GRAPHQL_ERROR_CHARS: usize = 1_024;

#[derive(Parser)]
#[command(
    name = "wand",
    version,
    about = "Read Wiz issues and vulnerability findings"
)]
pub struct Cli {
    #[arg(long, global = true, value_enum, default_value = "json")]
    pub output: OutputFormat,
    #[arg(long, global = true)]
    pub compact: bool,
    #[command(flatten)]
    connection: ConnectionArgs,
    #[command(subcommand)]
    command: Command,
}

impl Cli {
    pub fn try_parse_friendly() -> std::result::Result<Self, clap::Error> {
        let matches = friendly_command().try_get_matches()?;
        Self::from_arg_matches(&matches)
    }
}

fn friendly_command() -> clap::Command {
    let mut command = <Cli as CommandFactory>::command();
    let global_ids = command
        .get_arguments()
        .filter(|argument| argument.is_global_set())
        .map(|argument| argument.get_id().as_str().to_owned())
        .collect::<Vec<_>>();
    for id in global_ids {
        command = command.mut_arg(id.clone(), |argument| {
            decorate_argument(argument, "vulnerabilities", &id)
        });
    }
    for resource in ["issues", "vulnerabilities"] {
        command = command.mut_subcommand(resource, |resource_command| {
            resource_command.mut_subcommand("list", |mut list| {
                let ids = list
                    .get_arguments()
                    .map(|argument| argument.get_id().as_str().to_owned())
                    .collect::<Vec<_>>();
                for id in ids {
                    let resource = resource.to_owned();
                    list = list.mut_arg(id.clone(), move |argument| {
                        decorate_argument(argument, &resource, &id)
                    });
                }
                let example_query = if resource == "issues" {
                    "remediation"
                } else {
                    "container"
                };
                list.after_help(format!(
                    "Discover and search filters: wand {resource} filters [QUERY]\n\
                     Example: wand {resource} filters {example_query} --output table\n\
                     Multi-value filters may be repeated or comma-separated. Named filters override --filter JSON."
                ))
            })
        });
    }
    command
}

fn decorate_argument(mut argument: clap::Arg, resource: &str, id: &str) -> clap::Arg {
    const PAGINATION: &[&str] = &["limit", "page_size", "cursor", "max_pages"];
    const OUTPUT: &[&str] = &["output", "compact"];
    const CONNECTION: &[&str] = &[
        "endpoint",
        "auth_endpoint",
        "audience",
        "client_id",
        "allow_custom_endpoints",
    ];
    const TRANSPORT: &[&str] = &["timeout", "retries", "max_response_bytes"];
    let heading = if PAGINATION.contains(&id) {
        "Pagination"
    } else if OUTPUT.contains(&id) {
        "Output"
    } else if CONNECTION.contains(&id) {
        "Connection"
    } else if TRANSPORT.contains(&id) {
        "Transport safety"
    } else if id == "filter" {
        "Advanced"
    } else {
        filter_category(resource, id)
    };
    if is_boolean_filter(id) {
        argument = argument.num_args(0..=1).default_missing_value("true");
    }
    if id.ends_with("_after") || id.ends_with("_before") {
        argument = argument.value_parser(clap::builder::ValueParser::new(parse_rfc3339));
    }
    if (id.starts_with("min_") || id.starts_with("max_")) && id.ends_with("score") {
        argument = argument.value_parser(clap::builder::ValueParser::new(parse_score));
    }
    if let Some(parser) = filter_value_parser(resource, id) {
        argument = argument.value_parser(parser);
    } else if matches!(argument.get_action(), clap::ArgAction::Append) {
        argument = argument.value_parser(clap::builder::ValueParser::new(parse_nonempty));
    }
    if resource == "vulnerabilities" && id == "project" {
        argument = argument
            .help("Project UUID, or an exact name/slug when credentials include read:projects");
    }
    if resource == "issues" && id == "project" {
        argument = argument.help("Project UUID (issue filters do not accept project names)");
    }
    if resource == "vulnerabilities" && id == "container_registry" {
        argument = argument.help("Container registry name or Wiz UUID");
    }
    if resource == "vulnerabilities" && id == "container_repository" {
        argument = argument.help("Container repository name/path or Wiz UUID");
    }
    if resource == "vulnerabilities" && id == "base_container_image" {
        argument = argument.help("Base image name, digest, or Wiz UUID");
    }
    if argument.get_help().is_none() {
        let description = match id {
            "output" => "Output format for results and errors".into(),
            "compact" => "Emit compact JSON instead of pretty-printed JSON".into(),
            "endpoint" => "Wiz GraphQL endpoint (or set WIZ_API_ENDPOINT)".into(),
            "auth_endpoint" => "Wiz OAuth token endpoint".into(),
            "audience" => "OAuth audience requested from Wiz".into(),
            "client_id" => "Wiz service-account client ID (or set WIZ_CLIENT_ID)".into(),
            "timeout" => "Request timeout in seconds".into(),
            "retries" => "Retries for transient failures".into(),
            "max_response_bytes" => "Maximum accepted response size in bytes".into(),
            _ => filter_description(resource, id),
        };
        argument = argument.help(description);
    }
    argument.help_heading(heading)
}

fn parse_rfc3339(value: &str) -> std::result::Result<String, String> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|_| value.to_owned())
        .map_err(|_| "expected an RFC 3339 timestamp such as 2026-08-21T14:30:00Z".into())
}

fn parse_score(value: &str) -> std::result::Result<f64, String> {
    let score = value
        .parse::<f64>()
        .map_err(|_| "expected a number from 0 through 10".to_owned())?;
    if score.is_finite() && (0.0..=10.0).contains(&score) {
        Ok(score)
    } else {
        Err("expected a number from 0 through 10".into())
    }
}

fn parse_nonempty(value: &str) -> std::result::Result<String, String> {
    let value = value.trim();
    if value.is_empty() {
        Err("value cannot be empty".into())
    } else {
        Ok(value.to_owned())
    }
}

fn is_boolean_filter(id: &str) -> bool {
    id.starts_with("has_")
        || id.starts_with("is_")
        || id.ends_with("_is_set")
        || matches!(
            id,
            "validated_in_runtime"
                | "validated_as_exploitable"
                | "effective_user_interaction_required"
                | "widely_used_as_sub_dependency"
                | "asset_has_high_privileges"
                | "asset_has_admin_privileges"
                | "asset_is_used_on_prem"
                | "asset_is_representative_resource"
        )
}

const VULNERABILITY_SEVERITY_VALUES: &[&str] = &["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
const ISSUE_SEVERITY_VALUES: &[&str] = &["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
const STATUS_VALUES: &[&str] = &["OPEN", "IN_PROGRESS", "RESOLVED", "REJECTED"];
const ISSUE_TYPE_VALUES: &[&str] = &[
    "TOXIC_COMBINATION",
    "THREAT_DETECTION",
    "CLOUD_CONFIGURATION",
    "ATTACK_SURFACE",
    "RISK_TOXIC_COMBINATION",
];
const REACHABILITY_VALUES: &[&str] = &[
    "UNCHECKED",
    "UNSUPPORTED",
    "UNKNOWN",
    "NOT_REACHABLE",
    "USED_DEPENDENCY",
    "REACHABLE",
];
const RUNTIME_RESULT_VALUES: &[&str] = &[
    "UNCHECKED",
    "NO_RUNTIME_DATA",
    "PENDING_ACTIVITY",
    "LOADED",
    "EXECUTED",
];
const DETECTION_METHOD_VALUES: &[&str] = &[
    "UNKNOWN",
    "PACKAGE",
    "LIBRARY",
    "CONFIG_FILE",
    "OPEN_PORT",
    "STARTUP_SERVICE",
    "CONFIGURATION",
    "CLONED_REPOSITORY",
    "OS",
    "ARTIFACTS_ON_DISK",
    "WINDOWS_REGISTRY",
    "INSTALLED_PROGRAM",
    "FILE_PATH",
    "WINDOWS_SERVICE",
    "INSTALLED_PROGRAM_BY_SERVICE",
    "HOSTED_DATABASE_SCAN",
    "EXTERNAL_NETWORK_SCAN",
    "CLOUD_API",
    "THIRD_PARTY_AGENT",
    "AI_MODEL",
    "SAST_SCAN",
    "IDE_EXTENSION",
    "CONTAINER_IMAGE",
    "CI_COMPONENT",
];

fn filter_possible_values(resource: &str, id: &str) -> Option<&'static [&'static str]> {
    match (resource, id) {
        ("issues", "severity") => Some(ISSUE_SEVERITY_VALUES),
        ("vulnerabilities", "related_issue_severity") => Some(ISSUE_SEVERITY_VALUES),
        (
            "vulnerabilities",
            "severity" | "vendor_severity" | "nvd_severity" | "weighted_severity",
        ) => Some(VULNERABILITY_SEVERITY_VALUES),
        (_, "status") => Some(STATUS_VALUES),
        ("issues", "type") => Some(ISSUE_TYPE_VALUES),
        ("vulnerabilities", "reachability") => Some(REACHABILITY_VALUES),
        ("vulnerabilities", "runtime_validation_result") => Some(RUNTIME_RESULT_VALUES),
        ("vulnerabilities", "detection_method") => Some(DETECTION_METHOD_VALUES),
        _ => None,
    }
}

fn filter_value_parser(resource: &str, id: &str) -> Option<clap::builder::ValueParser> {
    let parser: fn(&str) -> std::result::Result<String, String> = match (resource, id) {
        ("issues", "severity") | ("vulnerabilities", "related_issue_severity") => {
            parse_issue_severity
        }
        (
            "vulnerabilities",
            "severity" | "vendor_severity" | "nvd_severity" | "weighted_severity",
        ) => parse_vulnerability_severity,
        (_, "status") => parse_finding_status,
        ("issues", "type") => parse_issue_type,
        ("vulnerabilities", "reachability") => parse_reachability,
        ("vulnerabilities", "runtime_validation_result") => parse_runtime_result,
        ("vulnerabilities", "detection_method") => parse_detection_method,
        _ => return None,
    };
    Some(clap::builder::ValueParser::new(parser))
}

fn parse_allowed(value: &str, allowed: &[&str]) -> std::result::Result<String, String> {
    let value = value.trim().to_ascii_uppercase();
    if allowed.contains(&value.as_str()) {
        Ok(value)
    } else {
        Err(format!(
            "invalid value; expected one of: {}",
            allowed.join(", ")
        ))
    }
}

fn parse_issue_severity(value: &str) -> std::result::Result<String, String> {
    parse_allowed(value, ISSUE_SEVERITY_VALUES)
}

fn parse_vulnerability_severity(value: &str) -> std::result::Result<String, String> {
    parse_allowed(value, VULNERABILITY_SEVERITY_VALUES)
}

fn parse_finding_status(value: &str) -> std::result::Result<String, String> {
    parse_allowed(value, STATUS_VALUES)
}

fn parse_issue_type(value: &str) -> std::result::Result<String, String> {
    parse_allowed(value, ISSUE_TYPE_VALUES)
}

fn parse_reachability(value: &str) -> std::result::Result<String, String> {
    parse_allowed(value, REACHABILITY_VALUES)
}

fn parse_runtime_result(value: &str) -> std::result::Result<String, String> {
    parse_allowed(value, RUNTIME_RESULT_VALUES)
}

fn parse_detection_method(value: &str) -> std::result::Result<String, String> {
    parse_allowed(value, DETECTION_METHOD_VALUES)
}

#[derive(Args)]
struct ConnectionArgs {
    #[arg(long, global = true, env = "WIZ_API_ENDPOINT", hide_env_values = true)]
    endpoint: Option<String>,
    #[arg(
        long,
        global = true,
        env = "WIZ_AUTH_ENDPOINT",
        hide_env_values = true,
        default_value = "https://auth.app.wiz.io/oauth/token"
    )]
    auth_endpoint: String,
    #[arg(
        long,
        global = true,
        env = "WIZ_AUDIENCE",
        hide_env_values = true,
        default_value = "wiz-api"
    )]
    audience: String,
    #[arg(long, global = true, env = "WIZ_CLIENT_ID", hide_env_values = true)]
    client_id: Option<String>,
    /// Permit non-wiz.io HTTPS endpoints. Credentials are sent to these endpoints.
    #[arg(long, global = true)]
    allow_custom_endpoints: bool,
    #[arg(long, global = true, env = "WAND_TIMEOUT", hide_env_values = true, default_value_t = 30,
        value_parser = clap::value_parser!(u64).range(1..=300))]
    timeout: u64,
    #[arg(long, global = true, env = "WAND_RETRIES", hide_env_values = true, default_value_t = 2,
        value_parser = clap::value_parser!(u8).range(0..=8))]
    retries: u8,
    #[arg(
        long,
        global = true,
        env = "WAND_MAX_RESPONSE_BYTES",
        hide_env_values = true,
        default_value_t = 10_485_760,
        value_parser = clap::value_parser!(u64).range(1024..=104_857_600)
    )]
    max_response_bytes: u64,
    #[arg(long, global = true, env = "WAND_ALLOW_INSECURE_HTTP", hide = true)]
    allow_insecure_http: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Validate Wiz credentials and API access.
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    /// Find and inspect Wiz issues.
    Issues {
        #[command(subcommand)]
        command: ReadCommand,
    },
    /// Find and inspect vulnerability findings.
    Vulnerabilities {
        #[command(subcommand)]
        command: VulnerabilityCommand,
    },
    /// Run an advanced read-only GraphQL query.
    Api {
        #[command(subcommand)]
        command: ApiCommand,
    },
    /// Inspect Wand's machine-readable command schema.
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },
    /// Generate a shell completion script.
    Completions { shell: Shell },
}

#[derive(Subcommand)]
enum AuthCommand {
    /// Validate credentials and access to the configured GraphQL endpoint.
    Check,
}

#[derive(Subcommand)]
enum ReadCommand {
    /// List issues using named filters and cursor pagination.
    List(Box<IssueListArgs>),
    /// Get one issue by ID.
    Get(GetArgs),
    /// List supported filters without connecting to Wiz.
    Filters(FilterCatalogArgs),
}

#[derive(Subcommand)]
enum VulnerabilityCommand {
    /// List vulnerability findings using named filters and cursor pagination.
    List(Box<VulnerabilityListArgs>),
    /// Get one vulnerability finding by ID.
    Get(GetArgs),
    /// List supported filters without connecting to Wiz.
    Filters(FilterCatalogArgs),
}

#[derive(Args)]
struct FilterCatalogArgs {
    /// Show only filters whose flag, category, description, or Wiz field contains this text.
    query: Option<String>,
}

#[derive(Args)]
struct GetArgs {
    id: String,
}

#[derive(Args)]
struct PageArgs {
    /// Maximum total records to return across pages.
    #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u32).range(1..=MAX_LIST_RECORDS as i64))]
    limit: u32,
    /// Maximum records requested per API call.
    #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u32).range(1..=500))]
    page_size: u32,
    /// Resume after this Wiz cursor.
    #[arg(long)]
    cursor: Option<String>,
    /// Safety bound on API calls, including empty pages.
    #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u32).range(1..=1000))]
    max_pages: u32,
}

#[derive(Args)]
struct CommonFilterArgs {
    /// Finding IDs. May be repeated or comma-separated.
    #[arg(long, value_delimiter = ',')]
    id: Vec<String>,
    /// Finding severities. May be repeated or comma-separated.
    #[arg(long, value_delimiter = ',')]
    severity: Vec<String>,
    /// Finding statuses. May be repeated or comma-separated.
    #[arg(long, value_delimiter = ',')]
    status: Vec<String>,
    /// Wiz project names or IDs. May be repeated or comma-separated.
    #[arg(long, value_delimiter = ',')]
    project: Vec<String>,
    /// Advanced Wiz filter object as JSON. Named flags take precedence.
    #[arg(long, default_value = "{}")]
    filter: String,
}

#[derive(Args)]
struct IssueListArgs {
    #[command(flatten)]
    page: PageArgs,
    #[command(flatten)]
    filters: CommonFilterArgs,
    #[arg(long, value_delimiter = ',')]
    r#type: Vec<String>,
    #[arg(long)]
    search: Option<String>,
    #[arg(long, value_delimiter = ',')]
    security_framework: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    security_category: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    security_subcategory: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    framework_category: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    stack_layer: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    resolution_reason: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    open_reason: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    risk_any: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    risk_all: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    cloud_account: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    threat_center_actor: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    threat_resolved_by: Vec<String>,
    #[arg(long)]
    source_security_scan: Option<String>,
    #[arg(long)]
    service_ticket: Option<String>,
    #[arg(long)]
    note_contains: Option<String>,
    #[arg(long)]
    has_service_ticket: Option<bool>,
    #[arg(long)]
    has_remediation: Option<bool>,
    #[arg(long)]
    has_auto_remediation: Option<bool>,
    #[arg(long)]
    has_code_remediation: Option<bool>,
    #[arg(long)]
    has_ai_remediation_analysis: Option<bool>,
    #[arg(long)]
    has_due_date: Option<bool>,
    #[arg(long)]
    has_note: Option<bool>,
    #[arg(long)]
    has_user_note: Option<bool>,
    #[arg(long)]
    project_is_set: Option<bool>,
    #[arg(long)]
    risk_is_set: Option<bool>,
    #[arg(long)]
    validated_as_exploitable: Option<bool>,
    #[arg(long)]
    created_after: Option<String>,
    #[arg(long)]
    created_before: Option<String>,
    #[arg(long)]
    resolved_after: Option<String>,
    #[arg(long)]
    resolved_before: Option<String>,
    #[arg(long)]
    status_changed_after: Option<String>,
    #[arg(long)]
    status_changed_before: Option<String>,
    #[arg(long)]
    due_after: Option<String>,
    #[arg(long)]
    due_before: Option<String>,
}

#[derive(Args)]
struct VulnerabilityListArgs {
    #[command(flatten)]
    page: PageArgs,
    #[command(flatten)]
    filters: CommonFilterArgs,
    /// Vulnerable asset IDs. May be repeated or comma-separated.
    #[arg(long, value_delimiter = ',')]
    asset_id: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    asset_type: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    cloud_platform: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    subscription: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    region: Vec<String>,
    #[arg(long)]
    has_exploit: Option<bool>,
    /// Only findings in CISA's Known Exploited Vulnerabilities catalog.
    #[arg(long)]
    has_cisa_kev_exploit: Option<bool>,
    /// Only findings for which Wiz reports a fix.
    #[arg(long)]
    has_fix: Option<bool>,
    #[arg(long)]
    is_malicious_package: Option<bool>,
    #[arg(long)]
    validated_in_runtime: Option<bool>,
    #[arg(long)]
    is_high_profile_threat: Option<bool>,
    #[arg(long)]
    has_related_issue: Option<bool>,
    #[arg(long)]
    is_asset_accessible_from_internet: Option<bool>,
    #[arg(long)]
    is_asset_open_to_all_internet: Option<bool>,
    #[arg(long)]
    asset_has_high_privileges: Option<bool>,
    #[arg(long)]
    asset_has_admin_privileges: Option<bool>,
    #[arg(long)]
    is_scanned_from_workload: Option<bool>,
    #[arg(long)]
    is_scanned_from_registry: Option<bool>,
    #[arg(long)]
    is_scanned_from_sensor: Option<bool>,
    #[arg(long)]
    is_base_layer: Option<bool>,
    #[arg(long)]
    asset_is_used_on_prem: Option<bool>,
    #[arg(long)]
    has_external_source: Option<bool>,
    #[arg(long)]
    has_triggerable_remediation: Option<bool>,
    #[arg(long)]
    is_operating_system_end_of_life: Option<bool>,
    #[arg(long)]
    is_end_of_life: Option<bool>,
    #[arg(long)]
    effective_user_interaction_required: Option<bool>,
    #[arg(long)]
    has_initial_access_potential: Option<bool>,
    #[arg(long)]
    is_client_side: Option<bool>,
    #[arg(long)]
    widely_used_as_sub_dependency: Option<bool>,
    #[arg(long)]
    is_transitive: Option<bool>,
    #[arg(long)]
    asset_is_representative_resource: Option<bool>,
    #[arg(long)]
    has_source_mapped_code_findings: Option<bool>,
    #[arg(long)]
    has_source_mapped_code_resources: Option<bool>,
    #[arg(long)]
    has_source_mapped_cloud_findings: Option<bool>,
    /// Vulnerability/CVE identifiers. May be repeated or comma-separated.
    #[arg(long, value_delimiter = ',')]
    cve: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    vendor_severity: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    nvd_severity: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    weighted_severity: Vec<String>,
    /// Detection methods. May be repeated or comma-separated.
    #[arg(long, value_delimiter = ',')]
    detection_method: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    runtime_validation_result: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    reachability: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    asset_status: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    project_business_impact: Vec<String>,
    /// Installed package names. May be repeated or comma-separated.
    #[arg(long, value_delimiter = ',')]
    package_name: Vec<String>,
    /// Installed package versions. May be repeated or comma-separated.
    #[arg(long, value_delimiter = ',')]
    package_version: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    fixed_version: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    package_path: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    container_registry: Vec<String>,
    /// Container repository names. May be repeated or comma-separated.
    #[arg(long, value_delimiter = ',')]
    container_repository: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    base_container_image: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    image_layer_id: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    container_service_id: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    kubernetes_cluster_id: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    kubernetes_namespace_id: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    kubernetes_namespace: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    vcs_repository_id: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    related_issue_severity: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    code_to_cloud_pipeline_stage: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    effective_attack_vector: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    duplication: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    source_mapped_code_resource_id: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    source_mapped_code_repository_id: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    source_mapped_code_finding_id: Vec<String>,
    /// Minimum Wiz vulnerability score (exclusive).
    #[arg(long)]
    min_score: Option<f64>,
    /// Maximum Wiz vulnerability score (exclusive).
    #[arg(long)]
    max_score: Option<f64>,
    #[arg(long)]
    min_vendor_score: Option<f64>,
    #[arg(long)]
    max_vendor_score: Option<f64>,
    #[arg(long)]
    min_nvd_score: Option<f64>,
    #[arg(long)]
    max_nvd_score: Option<f64>,
    #[arg(long)]
    min_cna_score: Option<f64>,
    #[arg(long)]
    max_cna_score: Option<f64>,
    /// Findings updated after this RFC 3339 timestamp.
    #[arg(long)]
    updated_after: Option<String>,
    /// Findings updated before this RFC 3339 timestamp.
    #[arg(long)]
    updated_before: Option<String>,
    #[arg(long)]
    first_seen_after: Option<String>,
    #[arg(long)]
    first_seen_before: Option<String>,
    #[arg(long)]
    fixed_after: Option<String>,
    #[arg(long)]
    fixed_before: Option<String>,
    #[arg(long)]
    resolved_after: Option<String>,
    #[arg(long)]
    resolved_before: Option<String>,
    #[arg(long)]
    status_updated_after: Option<String>,
    #[arg(long)]
    status_updated_before: Option<String>,
    #[arg(long)]
    published_after: Option<String>,
    #[arg(long)]
    published_before: Option<String>,
    #[arg(long)]
    cisa_kev_due_after: Option<String>,
    #[arg(long)]
    cisa_kev_due_before: Option<String>,
}

#[derive(Subcommand)]
enum ApiCommand {
    /// Execute an arbitrary query operation. Mutations and subscriptions are rejected.
    Graphql(RawArgs),
}

#[derive(Args)]
struct RawArgs {
    #[arg(
        long,
        conflicts_with = "query_file",
        required_unless_present = "query_file"
    )]
    query: Option<String>,
    /// GraphQL file path, or - to read from stdin.
    #[arg(long, conflicts_with = "query")]
    query_file: Option<PathBuf>,
    #[arg(long, default_value = "{}")]
    variables: String,
    #[arg(long)]
    operation_name: Option<String>,
    /// Return partial data with GraphQL errors in metadata instead of failing.
    #[arg(long)]
    allow_partial: bool,
}

#[derive(Subcommand)]
enum AgentCommand {
    Schema,
}

pub async fn run(cli: Cli) -> Result<()> {
    validate_command_inputs(&cli.command)?;
    let value = match cli.command {
        Command::Agent {
            command: AgentCommand::Schema,
        } => agent_schema(),
        Command::Completions { shell } => {
            generate(shell, &mut friendly_command(), "wand", &mut io::stdout());
            return Ok(());
        }
        Command::Issues {
            command: ReadCommand::Filters(args),
        } => filter_catalog("issues", args),
        Command::Vulnerabilities {
            command: VulnerabilityCommand::Filters(args),
        } => filter_catalog("vulnerabilities", args),
        Command::Api {
            command: ApiCommand::Graphql(args),
        } => {
            let prepared = prepare_raw(args)?;
            let config = cli.connection.build()?;
            let client = WizClient::authenticate(config).await?;
            execute_raw(&client, prepared).await?
        }
        command => {
            let config = cli.connection.build()?;
            let client = WizClient::authenticate(config).await?;
            match command {
                Command::Auth {
                    command: AuthCommand::Check,
                } => auth_check(&client).await?,
                Command::Issues {
                    command: ReadCommand::List(args),
                } => {
                    let mut filter = common_filter(args.filters, false)?;
                    insert_list(&mut filter, "type", normalized(args.r#type));
                    insert_scalar(&mut filter, "search", args.search);
                    insert_list(&mut filter, "securityFramework", args.security_framework);
                    insert_list(&mut filter, "securityCategory", args.security_category);
                    insert_list(
                        &mut filter,
                        "securitySubCategory",
                        args.security_subcategory,
                    );
                    insert_list(&mut filter, "frameworkCategory", args.framework_category);
                    insert_list(&mut filter, "stackLayer", normalized(args.stack_layer));
                    insert_list(
                        &mut filter,
                        "resolutionReason",
                        normalized(args.resolution_reason),
                    );
                    insert_list(&mut filter, "openReason", normalized(args.open_reason));
                    insert_list(&mut filter, "riskEqualsAny", args.risk_any);
                    insert_list(&mut filter, "riskEqualsAll", args.risk_all);
                    insert_list(
                        &mut filter,
                        "cloudAccountOrCloudOrganizationId",
                        args.cloud_account,
                    );
                    insert_list(&mut filter, "threatCenterActors", args.threat_center_actor);
                    insert_list(&mut filter, "threatResolvedBy", args.threat_resolved_by);
                    insert_scalar(&mut filter, "sourceSecurityScan", args.source_security_scan);
                    insert_scalar(&mut filter, "searchServiceTicket", args.service_ticket);
                    insert_scalar(&mut filter, "noteContains", args.note_contains);
                    insert_bool(&mut filter, "hasServiceTicket", args.has_service_ticket);
                    insert_bool(&mut filter, "hasRemediation", args.has_remediation);
                    insert_bool(&mut filter, "hasAutoRemediation", args.has_auto_remediation);
                    insert_bool(&mut filter, "hasCodeRemediation", args.has_code_remediation);
                    insert_bool(
                        &mut filter,
                        "hasAiRemediationAnalysis",
                        args.has_ai_remediation_analysis,
                    );
                    insert_bool(&mut filter, "hasDueDate", args.has_due_date);
                    insert_bool(&mut filter, "hasNote", args.has_note);
                    insert_bool(&mut filter, "hasUserNote", args.has_user_note);
                    insert_bool(&mut filter, "projectIsSet", args.project_is_set);
                    insert_bool(&mut filter, "riskIsSet", args.risk_is_set);
                    insert_bool(
                        &mut filter,
                        "validatedAsExploitable",
                        args.validated_as_exploitable,
                    );
                    insert_date_range(
                        &mut filter,
                        "createdAt",
                        args.created_after,
                        args.created_before,
                    )?;
                    insert_date_range(
                        &mut filter,
                        "resolvedAt",
                        args.resolved_after,
                        args.resolved_before,
                    )?;
                    insert_date_range(
                        &mut filter,
                        "statusChangedAt",
                        args.status_changed_after,
                        args.status_changed_before,
                    )?;
                    insert_date_range(&mut filter, "dueAt", args.due_after, args.due_before)?;
                    paginated(&client, ISSUES, args.page, Value::Object(filter)).await?
                }
                Command::Issues {
                    command: ReadCommand::Get(args),
                } => get_one(&client, ISSUES, args.id).await?,
                Command::Vulnerabilities {
                    command: VulnerabilityCommand::List(args),
                } => {
                    let project_ids = resolve_project_ids(&client, &args.filters.project).await?;
                    let mut filter = common_filter(args.filters, true)?;
                    insert_object_list(&mut filter, "projectIdV2", "equals", project_ids);
                    insert_object_list(&mut filter, "assetIdV2", "equals", args.asset_id);
                    insert_list(&mut filter, "assetType", normalized(args.asset_type));
                    insert_list(&mut filter, "cloudPlatforms", args.cloud_platform);
                    insert_list(&mut filter, "subscriptionExternalId", args.subscription);
                    insert_object_list(&mut filter, "assetRegion", "equals", args.region);
                    insert_bool(&mut filter, "hasExploit", args.has_exploit);
                    insert_bool(&mut filter, "hasCisaKevExploit", args.has_cisa_kev_exploit);
                    insert_bool(&mut filter, "hasFix", args.has_fix);
                    insert_bool(&mut filter, "isMaliciousPackage", args.is_malicious_package);
                    insert_bool(&mut filter, "validatedInRuntime", args.validated_in_runtime);
                    insert_bool(
                        &mut filter,
                        "isHighProfileThreat",
                        args.is_high_profile_threat,
                    );
                    insert_bool(&mut filter, "hasRelatedIssue", args.has_related_issue);
                    insert_bool(
                        &mut filter,
                        "isAssetAccessibleFromInternet",
                        args.is_asset_accessible_from_internet,
                    );
                    insert_bool(
                        &mut filter,
                        "isAssetOpenToAllInternet",
                        args.is_asset_open_to_all_internet,
                    );
                    insert_bool(
                        &mut filter,
                        "assetHasHighPrivileges",
                        args.asset_has_high_privileges,
                    );
                    insert_bool(
                        &mut filter,
                        "assetHasAdminPrivileges",
                        args.asset_has_admin_privileges,
                    );
                    insert_bool(
                        &mut filter,
                        "isScannedFromWorkload",
                        args.is_scanned_from_workload,
                    );
                    insert_bool(
                        &mut filter,
                        "isScannedFromRegistry",
                        args.is_scanned_from_registry,
                    );
                    insert_bool(
                        &mut filter,
                        "isScannedFromSensor",
                        args.is_scanned_from_sensor,
                    );
                    insert_bool(&mut filter, "isBaseLayer", args.is_base_layer);
                    insert_bool(&mut filter, "assetIsUsedOnPrem", args.asset_is_used_on_prem);
                    insert_bool(&mut filter, "hasExternalSource", args.has_external_source);
                    insert_bool(
                        &mut filter,
                        "hasTriggerableRemediation",
                        args.has_triggerable_remediation,
                    );
                    insert_bool(
                        &mut filter,
                        "isOperatingSystemEndOfLife",
                        args.is_operating_system_end_of_life,
                    );
                    insert_bool(&mut filter, "isEndOfLife", args.is_end_of_life);
                    insert_bool(
                        &mut filter,
                        "effectiveUserInteractionRequired",
                        args.effective_user_interaction_required,
                    );
                    insert_bool(
                        &mut filter,
                        "hasInitialAccessPotential",
                        args.has_initial_access_potential,
                    );
                    insert_bool(&mut filter, "isClientSide", args.is_client_side);
                    insert_bool(
                        &mut filter,
                        "widelyUsedAsSubDependency",
                        args.widely_used_as_sub_dependency,
                    );
                    insert_bool(&mut filter, "isTransitive", args.is_transitive);
                    insert_bool(
                        &mut filter,
                        "assetIsRepresentativeResource",
                        args.asset_is_representative_resource,
                    );
                    insert_bool(
                        &mut filter,
                        "hasSourceMappedCodeFindings",
                        args.has_source_mapped_code_findings,
                    );
                    insert_bool(
                        &mut filter,
                        "hasSourceMappedCodeResources",
                        args.has_source_mapped_code_resources,
                    );
                    insert_bool(
                        &mut filter,
                        "hasSourceMappedCloudFindings",
                        args.has_source_mapped_cloud_findings,
                    );
                    insert_object_list(
                        &mut filter,
                        "vulnerabilityExternalIdV2",
                        "equals",
                        args.cve,
                    );
                    insert_list(
                        &mut filter,
                        "vendorSeverity",
                        normalized(args.vendor_severity),
                    );
                    insert_list(&mut filter, "nvdSeverity", normalized(args.nvd_severity));
                    insert_list(
                        &mut filter,
                        "weightedSeverity",
                        normalized(args.weighted_severity),
                    );
                    insert_list(
                        &mut filter,
                        "detectionMethod",
                        normalized(args.detection_method),
                    );
                    insert_list(
                        &mut filter,
                        "runtimeValidationResult",
                        normalized(args.runtime_validation_result),
                    );
                    insert_list(&mut filter, "reachability", normalized(args.reachability));
                    insert_list(&mut filter, "assetStatus", normalized(args.asset_status));
                    insert_list(
                        &mut filter,
                        "projectBusinessImpact",
                        normalized(args.project_business_impact),
                    );
                    insert_list(&mut filter, "detailedName", args.package_name);
                    insert_object_list(&mut filter, "version", "equals", args.package_version);
                    insert_object_list(&mut filter, "fixedVersion", "equals", args.fixed_version);
                    insert_list(&mut filter, "locationPath", args.package_path);
                    let registry_ids =
                        resolve_container_registry_ids(&client, args.container_registry).await?;
                    insert_list(&mut filter, "containerRegistry", registry_ids);
                    let repository_ids =
                        resolve_container_repository_ids(&client, args.container_repository)
                            .await?;
                    insert_list(&mut filter, "containerRepository", repository_ids);
                    let base_image_ids =
                        resolve_container_image_ids(&client, args.base_container_image).await?;
                    insert_list(&mut filter, "baseContainerImage", base_image_ids);
                    insert_list(&mut filter, "layerId", args.image_layer_id);
                    insert_list(&mut filter, "containerServiceId", args.container_service_id);
                    insert_list(
                        &mut filter,
                        "kubernetesClusterId",
                        args.kubernetes_cluster_id,
                    );
                    insert_list(
                        &mut filter,
                        "kubernetesNamespaceId",
                        args.kubernetes_namespace_id,
                    );
                    insert_list(
                        &mut filter,
                        "kubernetesNamespaceName",
                        args.kubernetes_namespace,
                    );
                    insert_list(&mut filter, "vcsRepositoryId", args.vcs_repository_id);
                    insert_list(
                        &mut filter,
                        "relatedIssueSeverity",
                        normalized(args.related_issue_severity),
                    );
                    insert_list(
                        &mut filter,
                        "codeToCloudPipelineStage",
                        normalized(args.code_to_cloud_pipeline_stage),
                    );
                    insert_list(
                        &mut filter,
                        "effectiveAttackVector",
                        normalized(args.effective_attack_vector),
                    );
                    insert_list(&mut filter, "duplication", normalized(args.duplication));
                    insert_list(
                        &mut filter,
                        "sourceMappedCodeResourceIds",
                        args.source_mapped_code_resource_id,
                    );
                    insert_list(
                        &mut filter,
                        "sourceMappedCodeResourceRepositoryIds",
                        args.source_mapped_code_repository_id,
                    );
                    insert_list(
                        &mut filter,
                        "sourceMappedCodeFindingIds",
                        args.source_mapped_code_finding_id,
                    );
                    insert_number_range(&mut filter, "score", args.min_score, args.max_score)?;
                    insert_number_range(
                        &mut filter,
                        "vendorScore",
                        args.min_vendor_score,
                        args.max_vendor_score,
                    )?;
                    insert_number_range(
                        &mut filter,
                        "nvdScore",
                        args.min_nvd_score,
                        args.max_nvd_score,
                    )?;
                    insert_number_range(
                        &mut filter,
                        "cnaScore",
                        args.min_cna_score,
                        args.max_cna_score,
                    )?;
                    insert_date_range(
                        &mut filter,
                        "updatedAt",
                        args.updated_after,
                        args.updated_before,
                    )?;
                    insert_date_range(
                        &mut filter,
                        "firstSeenAt",
                        args.first_seen_after,
                        args.first_seen_before,
                    )?;
                    insert_date_range(&mut filter, "fixDate", args.fixed_after, args.fixed_before)?;
                    insert_date_range(
                        &mut filter,
                        "resolvedAt",
                        args.resolved_after,
                        args.resolved_before,
                    )?;
                    insert_date_range(
                        &mut filter,
                        "statusUpdatedAt",
                        args.status_updated_after,
                        args.status_updated_before,
                    )?;
                    insert_date_range(
                        &mut filter,
                        "publishedDate",
                        args.published_after,
                        args.published_before,
                    )?;
                    insert_date_range(
                        &mut filter,
                        "cisaKevDueDate",
                        args.cisa_kev_due_after,
                        args.cisa_kev_due_before,
                    )?;
                    paginated(&client, VULNERABILITIES, args.page, Value::Object(filter)).await?
                }
                Command::Vulnerabilities {
                    command: VulnerabilityCommand::Get(args),
                } => get_one(&client, VULNERABILITIES, args.id).await?,
                Command::Api { .. }
                | Command::Agent { .. }
                | Command::Completions { .. }
                | Command::Issues {
                    command: ReadCommand::Filters(_),
                }
                | Command::Vulnerabilities {
                    command: VulnerabilityCommand::Filters(_),
                } => {
                    unreachable!()
                }
            }
        }
    };
    let rendered = cli
        .output
        .render(&value, cli.compact)
        .map_err(Error::Response)?;
    println!("{rendered}");
    Ok(())
}

fn validate_command_inputs(command: &Command) -> Result<()> {
    match command {
        Command::Issues {
            command: ReadCommand::List(args),
        } => {
            graphql::parse_object(&args.filters.filter, "filter")?;
            if let Some(project) = args
                .filters
                .project
                .iter()
                .map(|project| project.trim())
                .find(|project| !looks_like_uuid(project))
            {
                return Err(Error::Input(format!(
                    "issue --project expects a project UUID, not {project:?}; vulnerability project names can be resolved by `wand vulnerabilities list`"
                )));
            }
            validate_date_pair("created", &args.created_after, &args.created_before)?;
            validate_date_pair("resolved", &args.resolved_after, &args.resolved_before)?;
            validate_date_pair(
                "status-changed",
                &args.status_changed_after,
                &args.status_changed_before,
            )?;
            validate_date_pair("due", &args.due_after, &args.due_before)?;
        }
        Command::Vulnerabilities {
            command: VulnerabilityCommand::List(args),
        } => {
            graphql::parse_object(&args.filters.filter, "filter")?;
            for (name, minimum, maximum) in [
                ("score", args.min_score, args.max_score),
                ("vendor-score", args.min_vendor_score, args.max_vendor_score),
                ("nvd-score", args.min_nvd_score, args.max_nvd_score),
                ("cna-score", args.min_cna_score, args.max_cna_score),
            ] {
                validate_number_pair(name, minimum, maximum)?;
            }
            for (name, after, before) in [
                ("updated", &args.updated_after, &args.updated_before),
                (
                    "first-seen",
                    &args.first_seen_after,
                    &args.first_seen_before,
                ),
                ("fixed", &args.fixed_after, &args.fixed_before),
                ("resolved", &args.resolved_after, &args.resolved_before),
                (
                    "status-updated",
                    &args.status_updated_after,
                    &args.status_updated_before,
                ),
                ("published", &args.published_after, &args.published_before),
                (
                    "cisa-kev-due",
                    &args.cisa_kev_due_after,
                    &args.cisa_kev_due_before,
                ),
            ] {
                validate_date_pair(name, after, before)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_date_pair(name: &str, after: &Option<String>, before: &Option<String>) -> Result<()> {
    if let (Some(after), Some(before)) = (after, before)
        && chrono::DateTime::parse_from_rfc3339(after)
            .map_err(|error| Error::Input(error.to_string()))?
            >= chrono::DateTime::parse_from_rfc3339(before)
                .map_err(|error| Error::Input(error.to_string()))?
    {
        return Err(Error::Input(format!(
            "--{name}-after must be earlier than --{name}-before"
        )));
    }
    Ok(())
}

fn validate_number_pair(name: &str, minimum: Option<f64>, maximum: Option<f64>) -> Result<()> {
    if let (Some(minimum), Some(maximum)) = (minimum, maximum)
        && minimum >= maximum
    {
        return Err(Error::Input(format!(
            "--min-{name} must be less than --max-{name}"
        )));
    }
    Ok(())
}

impl ConnectionArgs {
    fn build(self) -> Result<Config> {
        let required = |name: &str, value: Option<String>| {
            value
                .filter(|v| !v.is_empty())
                .ok_or_else(|| Error::Config(format!("{name} is required")))
        };
        let config = Config::new(
            required("WIZ_API_ENDPOINT", self.endpoint)?,
            self.auth_endpoint,
            self.audience,
            required("WIZ_CLIENT_ID", self.client_id)?,
            env::var("WIZ_CLIENT_SECRET")
                .ok()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| Error::Config("WIZ_CLIENT_SECRET is required".into()))?,
            self.allow_insecure_http,
            self.allow_custom_endpoints,
        )?;
        Ok(config.with_transport(self.timeout, self.retries, self.max_response_bytes as usize))
    }
}

async fn auth_check(client: &WizClient) -> Result<Value> {
    let response = client
        .query(AUTH_CHECK, json!({}), Some("WandAuthCheck"))
        .await?;
    complete_data(response.data, response.errors)?;
    Ok(envelope(
        json!({"authenticated":true,"graphql_access":true}),
        json!({}),
    ))
}

async fn resolve_container_repository_ids(
    client: &WizClient,
    repositories: Vec<String>,
) -> Result<Vec<String>> {
    let mut ids = Vec::with_capacity(repositories.len());
    for repository in cleaned(repositories) {
        if looks_like_uuid(&repository) {
            ids.push(repository);
            continue;
        }
        let mut search_terms = vec![repository.as_str()];
        if let Some((_, name)) = repository.split_once('/')
            && name != repository
        {
            search_terms.push(name);
        }
        let mut matches = Map::new();
        for search in search_terms {
            let response = client
                .query(
                    CONTAINER_REPOSITORIES,
                    json!({"search":search}),
                    Some("ContainerRepositoriesByName"),
                )
                .await?;
            let data = complete_data(response.data, response.errors)?;
            reject_truncated_lookup(&data, "container repository", search)?;
            let nodes = data["page"]["nodes"].as_array().ok_or_else(|| {
                Error::Response("repository lookup response is missing data.page.nodes".into())
            })?;
            for node in nodes {
                let Some(id) = node["id"].as_str() else {
                    continue;
                };
                if repository_matches(node, &repository) {
                    matches.insert(id.to_owned(), node.clone());
                }
            }
            if matches.len() == 1 {
                break;
            }
        }
        match matches.len() {
            0 => {
                return Err(Error::NotFound(format!(
                    "no container repository matched {repository:?}; pass its Wiz UUID or check `wand vulnerabilities filters`"
                )));
            }
            1 => ids.push(matches.keys().next().unwrap().to_owned()),
            count => {
                let choices = matches
                    .values()
                    .take(10)
                    .filter_map(|node| {
                        node["externalId"]
                            .as_str()
                            .or_else(|| node["name"].as_str())
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(Error::Response(format!(
                    "container repository {repository:?} matched {count} repositories ({choices}); pass a Wiz UUID"
                )));
            }
        }
    }
    ids.sort();
    ids.dedup();
    Ok(ids)
}

async fn resolve_project_ids(client: &WizClient, projects: &[String]) -> Result<Vec<String>> {
    let mut ids = Vec::with_capacity(projects.len());
    for project in cleaned(projects.to_vec()) {
        if looks_like_uuid(&project) {
            ids.push(project.clone());
            continue;
        }
        let response = client
            .query(PROJECTS, json!({"search":project}), Some("ProjectsByName"))
            .await?;
        if response
            .errors
            .iter()
            .any(|error| error.message.contains("read:projects"))
        {
            return Err(Error::Authorization(format!(
                "resolving project name {project:?} requires read:projects; grant that scope or pass the project UUID"
            )));
        }
        let data = complete_data(response.data, response.errors)?;
        reject_truncated_lookup(&data, "project", &project)?;
        let nodes = data["page"]["nodes"].as_array().ok_or_else(|| {
            Error::Response("project lookup response is missing data.page.nodes".into())
        })?;
        let matches = nodes
            .iter()
            .filter(|node| {
                ["name", "slug"].into_iter().any(|field| {
                    node[field]
                        .as_str()
                        .is_some_and(|value| value.eq_ignore_ascii_case(&project))
                })
            })
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [matched] => ids.push(
                matched["id"]
                    .as_str()
                    .ok_or_else(|| {
                        Error::Response("project lookup result is missing an id".into())
                    })?
                    .to_owned(),
            ),
            [] => {
                return Err(Error::NotFound(format!(
                    "no Wiz project matched {project:?}; pass an exact project name, slug, or UUID"
                )));
            }
            matched => {
                let choices = matched
                    .iter()
                    .take(10)
                    .filter_map(|project| project["name"].as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(Error::Response(format!(
                    "project name {project:?} is ambiguous ({choices}); pass a project slug or UUID"
                )));
            }
        }
    }
    ids.sort();
    ids.dedup();
    Ok(ids)
}

async fn resolve_container_registry_ids(
    client: &WizClient,
    registries: Vec<String>,
) -> Result<Vec<String>> {
    let mut ids = Vec::with_capacity(registries.len());
    for registry in cleaned(registries) {
        if looks_like_uuid(&registry) {
            ids.push(registry);
            continue;
        }
        let response = client
            .query(
                CONTAINER_REGISTRIES,
                json!({"search":registry}),
                Some("ContainerRegistriesByName"),
            )
            .await?;
        let data = complete_data(response.data, response.errors)?;
        reject_truncated_lookup(&data, "container registry", &registry)?;
        let nodes = data["page"]["nodes"].as_array().ok_or_else(|| {
            Error::Response("registry lookup response is missing data.page.nodes".into())
        })?;
        let matches = nodes
            .iter()
            .filter(|node| {
                ["name", "externalId"].into_iter().any(|field| {
                    node[field]
                        .as_str()
                        .is_some_and(|value| value.eq_ignore_ascii_case(&registry))
                })
            })
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [matched] => ids.push(
                matched["id"]
                    .as_str()
                    .ok_or_else(|| {
                        Error::Response("registry lookup result is missing an id".into())
                    })?
                    .to_owned(),
            ),
            [] => {
                return Err(Error::NotFound(format!(
                    "no container registry matched {registry:?}; pass an exact registry name or Wiz UUID"
                )));
            }
            matched => {
                let choices = matched
                    .iter()
                    .take(10)
                    .filter_map(|registry| registry["name"].as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(Error::Response(format!(
                    "container registry {registry:?} is ambiguous ({choices}); pass a Wiz UUID"
                )));
            }
        }
    }
    ids.sort();
    ids.dedup();
    Ok(ids)
}

async fn resolve_container_image_ids(
    client: &WizClient,
    images: Vec<String>,
) -> Result<Vec<String>> {
    let mut ids = Vec::with_capacity(images.len());
    for image in cleaned(images) {
        if looks_like_uuid(&image) {
            ids.push(image);
            continue;
        }
        let response = client
            .query(
                CONTAINER_IMAGES,
                json!({"search":image}),
                Some("ContainerImagesByName"),
            )
            .await?;
        let data = complete_data(response.data, response.errors)?;
        reject_truncated_lookup(&data, "container image", &image)?;
        let nodes = data["page"]["nodes"].as_array().ok_or_else(|| {
            Error::Response("container image lookup response is missing data.page.nodes".into())
        })?;
        let exact = nodes
            .iter()
            .filter(|node| {
                ["name", "shortName", "digest"].into_iter().any(|field| {
                    node[field]
                        .as_str()
                        .is_some_and(|value| value.eq_ignore_ascii_case(&image))
                })
            })
            .collect::<Vec<_>>();
        let matches = exact;
        match matches.as_slice() {
            [matched] => ids.push(
                matched["id"]
                    .as_str()
                    .ok_or_else(|| {
                        Error::Response("container image lookup result is missing an id".into())
                    })?
                    .to_owned(),
            ),
            [] => {
                return Err(Error::NotFound(format!(
                    "no container image matched {image:?}; pass an exact image name, digest, or Wiz UUID"
                )));
            }
            matched => {
                let choices = matched
                    .iter()
                    .take(10)
                    .filter_map(|image| image["name"].as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(Error::Response(format!(
                    "container image {image:?} is ambiguous ({choices}); pass a digest or Wiz UUID"
                )));
            }
        }
    }
    ids.sort();
    ids.dedup();
    Ok(ids)
}

fn reject_truncated_lookup(data: &Value, entity: &str, search: &str) -> Result<()> {
    if data["page"]["pageInfo"]["hasNextPage"].as_bool() == Some(true) {
        return Err(Error::Response(format!(
            "{entity} lookup for {search:?} returned more than 100 candidates; use a more exact name or pass the Wiz UUID"
        )));
    }
    Ok(())
}

fn repository_matches(node: &Value, requested: &str) -> bool {
    let mut names = ["externalId", "name", "shortName"]
        .into_iter()
        .filter_map(|field| node[field].as_str());
    if names
        .clone()
        .any(|name| name.eq_ignore_ascii_case(requested))
    {
        return true;
    }
    let registry = node["registry"]["name"].as_str();
    registry.is_some_and(|registry| {
        names.any(|name| format!("{registry}/{name}").eq_ignore_ascii_case(requested))
    })
}

fn looks_like_uuid(value: &str) -> bool {
    value.len() == 36
        && value
            .chars()
            .enumerate()
            .all(|(index, character)| match index {
                8 | 13 | 18 | 23 => character == '-',
                _ => character.is_ascii_hexdigit(),
            })
}

async fn get_one(client: &WizClient, query: &str, id: String) -> Result<Value> {
    let page = PageArgs {
        limit: 1,
        page_size: 1,
        cursor: None,
        max_pages: 1,
    };
    let result = paginated(client, query, page, json!({"id":id})).await?;
    let item = result["data"]
        .as_array()
        .and_then(|items| items.first())
        .cloned()
        .ok_or_else(|| Error::NotFound(format!("no result found for id {id}")))?;
    if item.get("id").and_then(Value::as_str) != Some(id.as_str()) {
        return Err(Error::Response(format!(
            "Wiz returned a different record while looking up id {id}"
        )));
    }
    Ok(envelope(
        item,
        json!({"count":1,"truncated":false,"next_cursor":null}),
    ))
}

async fn paginated(
    client: &WizClient,
    query: &str,
    page: PageArgs,
    filter: Value,
) -> Result<Value> {
    let mut nodes = Vec::new();
    let mut cursor = page.cursor;
    let mut requests = 0_u32;
    let mut output_bytes = 0_usize;
    let mut truncated = false;
    let mut seen_cursors = std::collections::HashSet::new();
    if let Some(value) = cursor.clone() {
        seen_cursors.insert(value);
    }
    loop {
        let remaining = page.limit as usize - nodes.len();
        if remaining == 0 {
            truncated = cursor.is_some();
            break;
        }
        let first = remaining.min(page.page_size as usize) as u32;
        let response = client
            .query(
                query,
                json!({"first":first,"after":cursor,"filterBy":filter}),
                None,
            )
            .await?;
        let mut data = complete_data(response.data, response.errors)?;
        let page_value = data
            .get_mut("page")
            .ok_or_else(|| Error::Response("response is missing data.page".into()))?;
        let page_nodes = page_value
            .get_mut("nodes")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| Error::Response("response is missing data.page.nodes array".into()))?;
        if page_nodes.len() > first as usize {
            return Err(Error::Response(format!(
                "Wiz returned {} nodes after Wand requested {first}",
                page_nodes.len()
            )));
        }
        let page_was_empty = page_nodes.is_empty();
        for node in page_nodes.drain(..).take(remaining) {
            output_bytes = output_bytes.saturating_add(
                serde_json::to_vec(&node)
                    .map_err(|error| Error::Response(error.to_string()))?
                    .len(),
            );
            if output_bytes > MAX_AGGREGATE_OUTPUT_BYTES {
                return Err(Error::Response(format!(
                    "combined result exceeds {MAX_AGGREGATE_OUTPUT_BYTES} byte limit"
                )));
            }
            nodes.push(node);
        }
        requests += 1;
        let info = page_value
            .get("pageInfo")
            .and_then(Value::as_object)
            .ok_or_else(|| Error::Response("response is missing data.page.pageInfo".into()))?;
        let has_next = info
            .get("hasNextPage")
            .and_then(Value::as_bool)
            .ok_or_else(|| Error::Response("pageInfo.hasNextPage is not a boolean".into()))?;
        let next = info
            .get("endCursor")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if !has_next {
            cursor = None;
            break;
        }
        if page_was_empty {
            return Err(Error::Response(
                "Wiz returned an empty page with hasNextPage=true".into(),
            ));
        }
        let next = next.ok_or_else(|| {
            Error::Response("hasNextPage is true but endCursor is missing".into())
        })?;
        if !seen_cursors.insert(next.clone()) {
            return Err(Error::Response("pagination cursor repeated".into()));
        }
        cursor = Some(next);
        if requests >= page.max_pages {
            truncated = true;
            break;
        }
        if nodes.len() >= page.limit as usize {
            truncated = true;
            break;
        }
    }
    let count = nodes.len();
    Ok(envelope(
        Value::Array(nodes),
        json!({
            "count":count,"truncated":truncated,"next_cursor":cursor,"requests":requests,"filter":filter
        }),
    ))
}

struct PreparedRaw {
    query: String,
    variables: Value,
    operation_name: Option<String>,
    allow_partial: bool,
}

fn prepare_raw(args: RawArgs) -> Result<PreparedRaw> {
    let query = match (args.query, args.query_file) {
        (Some(query), None) => query,
        (None, Some(path)) if path.as_os_str() == "-" => {
            let mut input = String::new();
            io::stdin()
                .take((MAX_GRAPHQL_INPUT_BYTES + 1) as u64)
                .read_to_string(&mut input)
                .map_err(|e| Error::Io(e.to_string()))?;
            input
        }
        (None, Some(path)) => read_limited(&path)?,
        _ => unreachable!(),
    };
    if query.len() > MAX_GRAPHQL_INPUT_BYTES {
        return Err(Error::Input(format!(
            "GraphQL query exceeds {MAX_GRAPHQL_INPUT_BYTES} byte limit"
        )));
    }
    if args.variables.len() > MAX_GRAPHQL_INPUT_BYTES {
        return Err(Error::Input(format!(
            "GraphQL variables exceed {MAX_GRAPHQL_INPUT_BYTES} byte limit"
        )));
    }
    graphql::ensure_read_only(&query, args.operation_name.as_deref())?;
    let variables = graphql::parse_object(&args.variables, "variables")?;
    Ok(PreparedRaw {
        query,
        variables,
        operation_name: args.operation_name,
        allow_partial: args.allow_partial,
    })
}

fn read_limited(path: &PathBuf) -> Result<String> {
    let metadata = fs::metadata(path)
        .map_err(|e| Error::Io(format!("failed to inspect {}: {e}", path.display())))?;
    if metadata.len() > MAX_GRAPHQL_INPUT_BYTES as u64 {
        return Err(Error::Input(format!(
            "GraphQL query exceeds {MAX_GRAPHQL_INPUT_BYTES} byte limit"
        )));
    }
    fs::read_to_string(path)
        .map_err(|e| Error::Io(format!("failed to read {}: {e}", path.display())))
}

async fn execute_raw(client: &WizClient, prepared: PreparedRaw) -> Result<Value> {
    let response = client
        .query(
            &prepared.query,
            prepared.variables,
            prepared.operation_name.as_deref(),
        )
        .await?;
    if !response.errors.is_empty() && !prepared.allow_partial {
        return Err(graphql_error(response.errors));
    }
    let partial = !response.errors.is_empty();
    let errors = safe_graphql_errors(response.errors);
    let data = match response.data {
        Some(data) => data,
        None if errors.is_empty() => {
            return Err(Error::Response("GraphQL response is missing data".into()));
        }
        None => return Err(graphql_error(errors)),
    };
    Ok(envelope(
        data,
        json!({"partial":partial,"graphql_errors":errors}),
    ))
}

fn complete_data(data: Option<Value>, errors: Vec<GraphqlError>) -> Result<Value> {
    if !errors.is_empty() {
        return Err(graphql_error(errors));
    }
    data.filter(|value| !value.is_null())
        .ok_or_else(|| Error::Response("GraphQL response is missing data".into()))
}

fn graphql_error(errors: Vec<GraphqlError>) -> Error {
    let errors = safe_graphql_errors(errors);
    let messages = errors
        .iter()
        .map(|e| e.message.as_str())
        .collect::<Vec<_>>()
        .join("; ");
    Error::Graphql {
        message: messages,
        details: json!(errors),
    }
}

fn safe_graphql_errors(errors: Vec<GraphqlError>) -> Vec<GraphqlError> {
    errors
        .into_iter()
        .take(MAX_GRAPHQL_ERRORS)
        .map(|mut error| {
            error.message = error
                .message
                .chars()
                .filter(|character| !character.is_control())
                .take(MAX_GRAPHQL_ERROR_CHARS)
                .collect();
            error.path = None;
            error.extensions = None;
            error
        })
        .collect()
}

fn common_filter(args: CommonFilterArgs, vulnerability: bool) -> Result<Map<String, Value>> {
    let mut filter = graphql::parse_object(&args.filter, "filter")?
        .as_object()
        .cloned()
        .unwrap();
    insert_list(&mut filter, "id", args.id);
    insert_list(&mut filter, "severity", normalized(args.severity));
    insert_list(&mut filter, "status", normalized(args.status));
    if !vulnerability {
        insert_list(&mut filter, "project", args.project);
    }
    Ok(filter)
}

fn normalized(values: Vec<String>) -> Vec<String> {
    cleaned(values)
        .into_iter()
        .map(|value| value.to_ascii_uppercase())
        .collect()
}

fn cleaned(values: Vec<String>) -> Vec<String> {
    let mut values = values
        .into_iter()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

fn insert_list(filter: &mut Map<String, Value>, key: &str, values: Vec<String>) {
    let values = cleaned(values);
    if !values.is_empty() {
        filter.insert(key.into(), json!(values));
    }
}

fn insert_object_list(
    filter: &mut Map<String, Value>,
    key: &str,
    operation: &str,
    values: Vec<String>,
) {
    let values = cleaned(values);
    if !values.is_empty() {
        let mut nested = filter
            .get(key)
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        nested.insert(operation.into(), json!(values));
        filter.insert(key.into(), Value::Object(nested));
    }
}

fn insert_bool(filter: &mut Map<String, Value>, key: &str, value: Option<bool>) {
    if let Some(value) = value {
        filter.insert(key.into(), json!(value));
    }
}

fn insert_scalar(filter: &mut Map<String, Value>, key: &str, value: Option<String>) {
    if let Some(value) = value {
        filter.insert(key.into(), json!(value));
    }
}

fn insert_date_range(
    filter: &mut Map<String, Value>,
    key: &str,
    after: Option<String>,
    before: Option<String>,
) -> Result<()> {
    validate_date_pair(&kebab_case_date_key(key), &after, &before)?;
    if after.is_some() || before.is_some() {
        let mut range = filter
            .get(key)
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        if let Some(value) = after {
            range.insert("after".into(), json!(value));
        }
        if let Some(value) = before {
            range.insert("before".into(), json!(value));
        }
        filter.insert(key.into(), Value::Object(range));
    }
    Ok(())
}

fn insert_number_range(
    filter: &mut Map<String, Value>,
    key: &str,
    minimum: Option<f64>,
    maximum: Option<f64>,
) -> Result<()> {
    validate_number_pair(&kebab_case_date_key(key), minimum, maximum)?;
    if minimum.is_some() || maximum.is_some() {
        let mut range = filter
            .get(key)
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        if let Some(value) = minimum {
            range.insert("greaterThan".into(), json!(value));
        }
        if let Some(value) = maximum {
            range.insert("lessThan".into(), json!(value));
        }
        filter.insert(key.into(), Value::Object(range));
    }
    Ok(())
}

fn kebab_case_date_key(key: &str) -> String {
    let mut output = String::new();
    for character in key.chars() {
        if character.is_ascii_uppercase() {
            output.push('-');
            output.push(character.to_ascii_lowercase());
        } else {
            output.push(character);
        }
    }
    match output.as_str() {
        "first-seen-at" => "first-seen".into(),
        "fix-date" => "fixed".into(),
        "published-date" => "published".into(),
        "cisa-kev-due-date" => "cisa-kev-due".into(),
        value => value.strip_suffix("-at").unwrap_or(value).into(),
    }
}

fn filter_catalog(resource: &str, args: FilterCatalogArgs) -> Value {
    let command = friendly_command();
    let list = command
        .find_subcommand(resource)
        .and_then(|command| command.find_subcommand("list"))
        .expect("list command exists");
    let excluded = [
        "limit",
        "page_size",
        "cursor",
        "max_pages",
        "filter",
        "endpoint",
        "auth_endpoint",
        "audience",
        "client_id",
        "allow_custom_endpoints",
        "timeout",
        "retries",
        "max_response_bytes",
        "allow_insecure_http",
        "output",
        "compact",
    ];
    let filters = list
        .get_arguments()
        .filter(|argument| !excluded.contains(&argument.get_id().as_str()))
        .filter_map(|argument| {
            let flag = argument.get_long()?;
            let id = argument.get_id().as_str();
            let (field, operation) = graphql_filter_mapping(resource, id);
            let category = filter_category(resource, id);
            let description = argument
                .get_help()
                .map(|help| help.to_string())
                .unwrap_or_else(|| filter_description(resource, id));
            let value = if is_boolean_filter(id) {
                "boolean; omit value for true"
            } else if matches!(argument.get_action(), clap::ArgAction::Append) {
                "one or more; repeat or comma-separate"
            } else {
                "single value"
            };
            let possible_values = filter_possible_values(resource, id);
            Some(json!({
                "flag": format!("--{flag}"),
                "category": category,
                "graphql_field": field,
                "operation": operation,
                "value": value,
                "possible_values": possible_values,
                "description": description,
                "repeatable_or_comma_separated": matches!(argument.get_action(), clap::ArgAction::Append),
            }))
        })
        .filter(|filter| {
            args.query.as_ref().is_none_or(|query| {
                let query = query.to_ascii_lowercase();
                ["flag", "category", "graphql_field", "description"]
                    .iter()
                    .any(|field| filter[*field].as_str().is_some_and(|value| value.to_ascii_lowercase().contains(&query)))
            })
        })
        .collect::<Vec<_>>();
    envelope(
        json!(filters),
        json!({
            "count":filters.len(),
            "resource": resource,
            "query": args.query,
            "usage": format!("wand {resource} list [FILTER FLAGS]"),
            "advanced_escape_hatch": "--filter JSON",
            "precedence": "named flags override conflicting keys supplied through --filter"
        }),
    )
}

fn filter_category(resource: &str, id: &str) -> &'static str {
    if id.ends_with("_after") || id.ends_with("_before") {
        return "Time";
    }
    if id.starts_with("min_") || id.starts_with("max_") || id.contains("severity") {
        return "Severity and score";
    }
    if id.contains("container") || id.contains("kubernetes") || id == "image_layer_id" {
        return "Container and Kubernetes";
    }
    if id.contains("package") || id == "fixed_version" || id.contains("transitive") {
        return "Package and dependency";
    }
    if id.starts_with("asset_") || matches!(id, "cloud_platform" | "subscription" | "region") {
        return "Asset and cloud";
    }
    if id.contains("remediation") || id.contains("fix") {
        return "Remediation";
    }
    if resource == "issues" && (id.contains("threat") || id.contains("risk")) {
        return "Risk and threat";
    }
    if id.contains("exploit")
        || id.contains("runtime")
        || id.contains("attack")
        || id.contains("reachability")
    {
        return "Exploitability and runtime";
    }
    if id.contains("source_mapped") || id.contains("vcs") || id.contains("pipeline") {
        return "Code and source mapping";
    }
    "Identity and classification"
}

fn filter_description(resource: &str, id: &str) -> String {
    let subject = lower_words(id);
    if let Some(score) = id.strip_prefix("min_") {
        return format!(
            "Exclusive lower bound for {} (0 through 10)",
            lower_words(score)
        );
    }
    if let Some(score) = id.strip_prefix("max_") {
        return format!(
            "Exclusive upper bound for {} (0 through 10)",
            lower_words(score)
        );
    }
    if let Some(field) = id.strip_suffix("_after") {
        return format!("{} after this RFC 3339 timestamp", sentence_case(field));
    }
    if let Some(field) = id.strip_suffix("_before") {
        return format!("{} before this RFC 3339 timestamp", sentence_case(field));
    }
    match resource {
        "issues" => format!("Filter issues by {subject}"),
        _ => format!("Filter vulnerability findings by {subject}"),
    }
}

fn lower_words(value: &str) -> String {
    value.replace('_', " ")
}

fn sentence_case(value: &str) -> String {
    let value = lower_words(value);
    let mut characters = value.chars();
    characters
        .next()
        .map(|first| first.to_uppercase().chain(characters).collect())
        .unwrap_or_default()
}

fn graphql_filter_mapping(resource: &str, id: &str) -> (String, Option<&'static str>) {
    let mapped = match (resource, id) {
        ("vulnerabilities", "project") => ("projectIdV2", Some("equals")),
        ("vulnerabilities", "asset_id") => ("assetIdV2", Some("equals")),
        ("vulnerabilities", "cve") => ("vulnerabilityExternalIdV2", Some("equals")),
        ("vulnerabilities", "cloud_platform") => ("cloudPlatforms", None),
        ("vulnerabilities", "subscription") => ("subscriptionExternalId", None),
        ("vulnerabilities", "region") => ("assetRegion", Some("equals")),
        ("vulnerabilities", "package_name") => ("detailedName", None),
        ("vulnerabilities", "package_version") => ("version", Some("equals")),
        ("vulnerabilities", "fixed_version") => ("fixedVersion", Some("equals")),
        ("vulnerabilities", "package_path") => ("locationPath", None),
        ("vulnerabilities", "image_layer_id") => ("layerId", None),
        ("vulnerabilities", "kubernetes_namespace") => ("kubernetesNamespaceName", None),
        ("vulnerabilities", "source_mapped_code_resource_id") => {
            ("sourceMappedCodeResourceIds", None)
        }
        ("vulnerabilities", "source_mapped_code_repository_id") => {
            ("sourceMappedCodeResourceRepositoryIds", None)
        }
        ("vulnerabilities", "source_mapped_code_finding_id") => {
            ("sourceMappedCodeFindingIds", None)
        }
        ("vulnerabilities", "first_seen_after") => ("firstSeenAt", Some("after")),
        ("vulnerabilities", "first_seen_before") => ("firstSeenAt", Some("before")),
        ("vulnerabilities", "fixed_after") => ("fixDate", Some("after")),
        ("vulnerabilities", "fixed_before") => ("fixDate", Some("before")),
        ("vulnerabilities", "status_updated_after") => ("statusUpdatedAt", Some("after")),
        ("vulnerabilities", "status_updated_before") => ("statusUpdatedAt", Some("before")),
        ("vulnerabilities", "cisa_kev_due_after") => ("cisaKevDueDate", Some("after")),
        ("vulnerabilities", "cisa_kev_due_before") => ("cisaKevDueDate", Some("before")),
        ("vulnerabilities", "updated_after") => ("updatedAt", Some("after")),
        ("vulnerabilities", "updated_before") => ("updatedAt", Some("before")),
        ("vulnerabilities", "resolved_after") => ("resolvedAt", Some("after")),
        ("vulnerabilities", "resolved_before") => ("resolvedAt", Some("before")),
        ("vulnerabilities", "published_after") => ("publishedDate", Some("after")),
        ("vulnerabilities", "published_before") => ("publishedDate", Some("before")),
        ("issues", "created_after") => ("createdAt", Some("after")),
        ("issues", "created_before") => ("createdAt", Some("before")),
        ("issues", "resolved_after") => ("resolvedAt", Some("after")),
        ("issues", "resolved_before") => ("resolvedAt", Some("before")),
        ("issues", "status_changed_after") => ("statusChangedAt", Some("after")),
        ("issues", "status_changed_before") => ("statusChangedAt", Some("before")),
        ("issues", "due_after") => ("dueAt", Some("after")),
        ("issues", "due_before") => ("dueAt", Some("before")),
        ("issues", "risk_any") => ("riskEqualsAny", None),
        ("issues", "risk_all") => ("riskEqualsAll", None),
        ("issues", "cloud_account") => ("cloudAccountOrCloudOrganizationId", None),
        ("issues", "threat_center_actor") => ("threatCenterActors", None),
        ("issues", "service_ticket") => ("searchServiceTicket", None),
        ("issues", "security_subcategory") => ("securitySubCategory", None),
        (_, id) if id.starts_with("min_") => (&id[4..], Some("greaterThan")),
        (_, id) if id.starts_with("max_") => (&id[4..], Some("lessThan")),
        (_, id) if id.ends_with("_after") => (&id[..id.len() - 6], Some("after")),
        (_, id) if id.ends_with("_before") => (&id[..id.len() - 7], Some("before")),
        _ => return (lower_camel(id), None),
    };
    (lower_camel(mapped.0), mapped.1)
}

fn lower_camel(value: &str) -> String {
    let mut parts = value.split('_');
    let mut output = parts.next().unwrap_or_default().to_owned();
    for part in parts {
        let mut chars = part.chars();
        if let Some(first) = chars.next() {
            output.extend(first.to_uppercase());
            output.extend(chars);
        }
    }
    output
}

fn agent_schema() -> Value {
    envelope(
        json!({
        "name":"wand","version":env!("CARGO_PKG_VERSION"),"read_only":true,"raw_graphql_guarantee":"mutation_and_subscription_syntax_blocked",
        "output":{"default":"json","formats":["json","yaml","table"],"schema_version":"1"},
        "schemas":{
            "success":{"required":["schema_version","data","meta"],"schema_version":"1"},
            "error":{"required":["schema_version","error.code","error.message"],"optional":["error.details"]}
        },
            "configuration":["WIZ_API_ENDPOINT","WIZ_AUTH_ENDPOINT","WIZ_AUDIENCE","WIZ_CLIENT_ID","WIZ_CLIENT_SECRET"],
            "commands":[
                {"path":"auth check","safety":"read","description":"Validate credentials and GraphQL access"},
                {"path":"issues list","safety":"read","example":"wand issues list --severity CRITICAL,HIGH --status OPEN --limit 200","filter_discovery":"wand issues filters","arguments":{"limit":"integer 1..10000","page-size":"integer 1..500","max-pages":"integer 1..1000","cursor":"string?","named_filters":"see filter_discovery","filter":"advanced JSON escape hatch"}},
                {"path":"issues get <id>","safety":"read","arguments":{"id":"required string"}},
                {"path":"issues filters","safety":"local","description":"List named issue filters and GraphQL mappings"},
                {"path":"vulnerabilities list","safety":"read","example":"wand vulnerabilities list --container-repository public.ecr.aws/datadog/agent --status OPEN","filter_discovery":"wand vulnerabilities filters","arguments":{"limit":"integer 1..10000","page-size":"integer 1..500","max-pages":"integer 1..1000","cursor":"string?","named_filters":"see filter_discovery","filter":"advanced JSON escape hatch"}},
                {"path":"vulnerabilities get <id>","safety":"read","arguments":{"id":"required string"}},
                {"path":"vulnerabilities filters","safety":"local","description":"List named vulnerability filters and GraphQL mappings"},
                {"path":"api graphql","safety":"read-validated","example":"wand api graphql --query-file query.graphql --variables '{\"first\":10}'","arguments":{"query":"string xor query-file","query-file":"path or -","variables":"JSON object","operation-name":"string?","allow-partial":"boolean"}},
                {"path":"agent schema","safety":"local"},
                {"path":"completions <shell>","safety":"local"}
            ],
            "exit_codes":{"0":"success","1":"API/response/I/O failure","2":"configuration or input","3":"authentication or authorization","4":"not found","5":"rate limit or transport"}
        }),
        json!({}),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn agent_schema_covers_every_top_level_command() {
        let clap_commands = Cli::command()
            .get_subcommands()
            .map(|command| command.get_name().to_owned())
            .collect::<BTreeSet<_>>();
        let schema = agent_schema();
        let schema_commands = schema["data"]["commands"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|command| command["path"].as_str())
            .filter_map(|path| path.split_whitespace().next())
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        assert_eq!(clap_commands, schema_commands);
    }
}
