use std::{
    env, fs,
    io::{self, Read as _},
    path::PathBuf,
};

use clap::{Args, CommandFactory, Parser, Subcommand};
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
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    Issues {
        #[command(subcommand)]
        command: ReadCommand,
    },
    Vulnerabilities {
        #[command(subcommand)]
        command: VulnerabilityCommand,
    },
    Api {
        #[command(subcommand)]
        command: ApiCommand,
    },
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
    List(IssueListArgs),
    Get(GetArgs),
}

#[derive(Subcommand)]
enum VulnerabilityCommand {
    List(VulnerabilityListArgs),
    Get(GetArgs),
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
    #[arg(long, value_delimiter = ',')]
    severity: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    status: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    project: Vec<String>,
    /// Additional Wiz filter object as JSON. Specific flags take precedence.
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
}

#[derive(Args)]
struct VulnerabilityListArgs {
    #[command(flatten)]
    page: PageArgs,
    #[command(flatten)]
    filters: CommonFilterArgs,
    #[arg(long)]
    has_exploit: Option<bool>,
    #[arg(long)]
    updated_after: Option<String>,
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
    let value = match cli.command {
        Command::Agent {
            command: AgentCommand::Schema,
        } => agent_schema(),
        Command::Completions { shell } => {
            generate(shell, &mut Cli::command(), "wand", &mut io::stdout());
            return Ok(());
        }
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
                    let mut filter = common_filter(args.filters)?;
                    insert_list(&mut filter, "type", args.r#type);
                    paginated(&client, ISSUES, args.page, Value::Object(filter)).await?
                }
                Command::Issues {
                    command: ReadCommand::Get(args),
                } => get_one(&client, ISSUES, args.id).await?,
                Command::Vulnerabilities {
                    command: VulnerabilityCommand::List(args),
                } => {
                    let mut filter = common_filter(args.filters)?;
                    if let Some(value) = args.has_exploit {
                        filter.insert("hasExploit".into(), json!(value));
                    }
                    if let Some(value) = args.updated_after {
                        filter.insert("updatedAt".into(), json!({"after":value}));
                    }
                    paginated(&client, VULNERABILITIES, args.page, Value::Object(filter)).await?
                }
                Command::Vulnerabilities {
                    command: VulnerabilityCommand::Get(args),
                } => get_one(&client, VULNERABILITIES, args.id).await?,
                Command::Api { .. } | Command::Agent { .. } | Command::Completions { .. } => {
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

fn common_filter(args: CommonFilterArgs) -> Result<Map<String, Value>> {
    let mut filter = graphql::parse_object(&args.filter, "filter")?
        .as_object()
        .cloned()
        .unwrap();
    insert_list(&mut filter, "severity", normalized(args.severity));
    insert_list(&mut filter, "status", normalized(args.status));
    insert_list(&mut filter, "project", args.project);
    Ok(filter)
}

fn normalized(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|value| value.to_ascii_uppercase())
        .collect()
}

fn insert_list(filter: &mut Map<String, Value>, key: &str, values: Vec<String>) {
    if !values.is_empty() {
        filter.insert(key.into(), json!(values));
    }
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
                {"path":"issues list","safety":"read","example":"wand issues list --severity CRITICAL,HIGH --status OPEN --limit 200","arguments":{"limit":"integer 1..10000","page-size":"integer 1..500","max-pages":"integer 1..1000","cursor":"string?","severity":"string[]","status":"string[]","project":"string[]","type":"string[]","filter":"JSON object"}},
                {"path":"issues get <id>","safety":"read","arguments":{"id":"required string"}},
                {"path":"vulnerabilities list","safety":"read","arguments":{"limit":"integer 1..10000","page-size":"integer 1..500","max-pages":"integer 1..1000","cursor":"string?","severity":"string[]","status":"string[]","project":"string[]","has-exploit":"boolean?","updated-after":"timestamp?","filter":"JSON object"}},
                {"path":"vulnerabilities get <id>","safety":"read","arguments":{"id":"required string"}},
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
