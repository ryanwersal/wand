# ADR 0001: Technology stack for an agent-first Wiz API CLI

- Status: Accepted for initial implementation
- Date: 2026-08-18
- Scope: architecture and MVP stack; no Wiz tenant schema was available during this research

## Context

The first useful version should retrieve Wiz issues and vulnerability findings without forcing a
human or an agent to interpret narrative reports. It should be easy to install, safe to automate,
predictable to parse, and pleasant enough for direct terminal use.

Datadog's Pup is the closest design reference. Pup is a Rust single-binary CLI built around `clap`,
`tokio`, `reqwest`, and `serde`. Its agent-oriented behavior includes machine-readable command
discovery, structured JSON/YAML output, metadata envelopes, and structured errors. Its command
shape is consistently `<domain> <action>`.

Wiz's integration API differs from Datadog's API in several important ways:

- It is a tenant-specific GraphQL endpoint, commonly shaped like
  `https://api.<region>.app.wiz.io/graphql`.
- Machine access uses an OAuth 2.0 service account and the client-credentials grant. Commercial
  tenants commonly use `https://auth.app.wiz.io/oauth/token` and audience `wiz-api`; legacy Auth0
  tenants can differ.
- Permissions are scope-based and may also be project-limited. An issues/vulnerabilities MVP should
  request only the corresponding read scopes.
- Public documentation is limited and much of the authoritative schema is tenant-gated. We should
  assume schema details can differ across tenants until verified against a real tenant.
- Wiz already distributes an unrelated scanning executable named `wizcli`.

## Decision

### Language and packaging

Use **stable Rust (edition 2024)** and ship a single native executable for macOS, Linux, and Windows.
Use `rustup`'s stable toolchain in development and commit `Cargo.lock`. Do not establish an MSRV
until the first release target matrix is known.

Rust is the best fit because it gives us Pup's deployment model, startup characteristics, strong
response modeling, and easy cross-platform release artifacts. Go is the credible alternative, but
matching Pup's architecture and reusing its proven CLI patterns outweighs Go's somewhat simpler
cross-compilation. TypeScript and Python are rejected for the core binary because runtime/package
management is needless friction for agents and CI runners.

The project and executable are named **Wand** / `wand`. This avoids colliding with Wiz's existing
`wizcli` scanner and makes the third-party nature of the tool clearer.

### Core crates

| Concern | Choice | Notes |
| --- | --- | --- |
| CLI | `clap` 4 derive + `clap_complete` | Typed commands, generated help/completions, command-tree introspection |
| Async | `tokio` 1 | Network I/O and future concurrent pagination |
| HTTP/TLS | `reqwest` with `rustls` | JSON/form requests, pooling, no system OpenSSL dependency |
| Data | `serde`, `serde_json`, `serde_yaml` | JSON is canonical; YAML is a presentation format |
| Errors | `thiserror` in library code, `anyhow` at CLI boundary | Typed programmatic errors plus useful context |
| Secrets | `secrecy`, `zeroize`, optional `keyring` | Reduce accidental credential exposure; OS store for named profiles |
| Config paths | `directories` | Native config locations without hand-written OS rules |
| URLs/time | `url`, `time` | Validate endpoints and timestamps |
| Diagnostics | `tracing`, `tracing-subscriber` | Logs go to stderr and must redact secrets |
| Testing | `cargo test`, `assert_cmd`, `predicates`, `wiremock`, `insta` | CLI contracts, HTTP behavior, and stable output snapshots |

Pin exact resolved versions in `Cargo.lock`, but use normal compatible version requirements in
`Cargo.toml`. Add dependencies only when the code needs them; the table is the target stack, not a
request to front-load every crate.

### Code organization

Start as one package with both a library and a thin binary:

```text
src/
  main.rs                 process boundary and exit codes
  lib.rs                  reusable application surface
  cli.rs                  clap command tree
  auth.rs                 token acquisition/cache and secret redaction
  client.rs               HTTP, retries, GraphQL protocol errors
  config.rs               profiles and precedence
  output.rs               stable envelopes and renderers
  commands/
    issues.rs
    vulnerabilities.rs
    api.rs                raw GraphQL escape hatch
graphql/
  issues.graphql
  vulnerability_findings.graphql
tests/
  cli_contract.rs
  api_contract.rs
```

Do not begin with a Cargo workspace or plugin system. Split crates only when there is a real second
consumer, such as an MCP server or WASM library.

### GraphQL approach

Use a small in-house transport on top of `reqwest`:

- Check named `.graphql` operations into the repository and embed them at compile time.
- Define typed variables and typed response projections with `serde`.
- Keep the outer GraphQL response generic enough to preserve both `data` and `errors`, because
  GraphQL can return partial data alongside errors.
- Do not generate a complete client from introspection in the MVP. A generated client would couple
  builds to a tenant/private schema and make drift harder to tolerate.
- Provide `wand api graphql --query-file ... --variables ...` for unsupported API operations.
- Later add `wand api schema` to inspect a tenant when permissions permit, while never requiring
  introspection for normal commands.

This produces typed, tested common workflows without pretending that the public schema is stable or
complete.

### Authentication and configuration

Support service-account client credentials first. No browser login is required for the MVP.

Configuration precedence is:

1. command flags;
2. environment variables;
3. selected named profile;
4. defaults.

Use `WIZ_API_ENDPOINT`, `WIZ_AUTH_ENDPOINT`, `WIZ_CLIENT_ID`, `WIZ_CLIENT_SECRET`, and
`WIZ_AUDIENCE`. Default the auth endpoint and audience only when the tenant type is known; never
guess the tenant GraphQL endpoint. Permit client ID/secret from environment for CI. For local named
profiles, store the secret in the OS keychain and non-secret metadata in a TOML config file. Never
accept a secret directly as a command-line flag, where process listings and shell history can expose
it.

Cache short-lived access tokens in memory. Persistent access-token caching is unnecessary for a
short-lived CLI process until measurements show otherwise.

### Agent-first interface contract

JSON is the default in every context. TTY detection must not silently change output shape. Humans
can request `--output table` or set it in their profile. YAML is available via `--output yaml`.

Rules for the process boundary:

- stdout contains exactly one data document; diagnostics and progress go to stderr;
- no color, spinner, prompt, or prose in JSON/YAML modes;
- all list commands accept `--limit`; pagination is automatic up to that limit;
- truncation and continuation state are explicit;
- timestamps are RFC 3339 UTC and identifiers remain strings;
- field names and envelope versions are compatibility contracts;
- reads never prompt; later mutations require explicit opt-in and confirmation, with a noninteractive
  `--yes` mechanism that does not auto-approve merely because an agent was detected;
- support `--jq` later only if it can operate locally and preserves well-defined exit behavior.

Successful output uses a versioned envelope:

```json
{
  "schema_version": "1",
  "data": [],
  "meta": {
    "count": 0,
    "truncated": false,
    "next_cursor": null,
    "warnings": []
  }
}
```

Errors use stable codes and actionable context without credentials. Authentication, authorization,
validation, transport, rate-limit, GraphQL, and partial-response errors must be distinguishable.
Use documented nonzero exit codes rather than collapsing every failure to `1`.

Expose `wand agent schema` as JSON describing commands, flags, enum values, output schemas, safety
level, and examples. Human `--help` remains human-readable even when invoked by an agent; explicit
machine discovery is more deterministic than environment-variable agent detection.

### Initial command surface

Keep the first vertical slice read-only:

```text
wand auth check
wand issues list|get
wand vulnerabilities list|get
wand api graphql
wand agent schema
```

Filtering should map directly to documented Wiz API filters instead of inventing a second query
language. Every list result must handle cursor pagination and expose the effective filters in
metadata when doing so does not leak sensitive values.

### Delivery and quality

Use GitHub Actions and a release tool such as `cargo-dist` after the first executable works. Target
signed archives/checksums and Homebrew initially; add other package managers based on demand.

Required CI checks should be `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
`cargo test`, dependency/license review, and secret scanning. Mock the OAuth and GraphQL servers in
tests; never require a live Wiz tenant in default CI. Maintain a separate opt-in tenant smoke test.

## Alternatives considered

### Generate the whole GraphQL client

Rejected for the MVP. It offers stronger compile-time coverage but requires an authoritative schema
snapshot, creates noisy churn, and can fail across tenant versions. Revisit after testing schema
stability across real tenants.

### Pass through arbitrary GraphQL only

Rejected as the primary UX. It is flexible but not discoverable, requires agents to manufacture
queries, and provides no stable output contract. It remains valuable as an escape hatch.

### Automatically detect agents and change behavior

Rejected as a core contract. Detection is useful for telemetry but makes scripts environment-
dependent. Explicit JSON defaults and `agent schema` give agents deterministic behavior.

## Risks and validation needed

- Obtain access to at least one Wiz tenant and export/inspect the allowed schema before implementing
  issue and vulnerability response models.
- Confirm Cognito versus legacy Auth0 token request fields, regional/Gov endpoints, token lifetime,
  pagination limits, rate-limit headers, and introspection policy with Wiz's tenant documentation.
- Capture representative issue and vulnerability responses, including partial GraphQL errors and
  nullability, as redacted contract fixtures.
- Confirm the minimum read scopes for every command.
- Check package-registry and trademark availability for Wand before the first public release.

## Sources

- [Datadog Pup repository and README](https://github.com/DataDog/pup)
- [Pup architecture](https://github.com/DataDog/pup/blob/main/docs/ARCHITECTURE.md)
- [Pup Rust dependencies](https://github.com/DataDog/pup/blob/main/Cargo.toml)
- [Microsoft's Wiz connector setup](https://learn.microsoft.com/en-us/defender-exposure-management/wiz-data-connector)
- [Panther's Wiz GraphQL ingestion documentation](https://docs.panther.com/data-onboarding/supported-logs/wiz)
- [Wiz GitHub organization](https://github.com/wiz-sec)

The Wiz sources available without a customer login establish the integration shape but do not expose
the complete customer GraphQL schema. Implementation must validate schema-specific claims against
the authenticated Wiz documentation or a real tenant.
