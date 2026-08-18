# Wand

Wand is a read-only, agent-first CLI for retrieving Wiz issues and vulnerability findings directly
from the tenant GraphQL API. Specific commands are primary; raw GraphQL is a read-only escape hatch.

## Configuration

```sh
export WIZ_API_ENDPOINT='https://api.us1.app.wiz.io/graphql'
export WIZ_CLIENT_ID='...'
export WIZ_CLIENT_SECRET='...'
# Optional: WIZ_AUTH_ENDPOINT (defaults to https://auth.app.wiz.io/oauth/token)
# Optional: WIZ_AUDIENCE (defaults to wiz-api)
```

## Commands

```sh
wand auth check
wand issues list --status OPEN --severity CRITICAL --severity HIGH
wand issues get <issue-id>
wand vulnerabilities list --status OPEN --severity CRITICAL
wand vulnerabilities get <finding-id>
wand api graphql --query-file query.graphql --variables '{"first":10}'
wand agent schema
```

JSON is the default and is never changed by TTY detection. YAML and compact human-oriented tables
are explicit alternatives:

```sh
wand issues list --output table
wand vulnerabilities get <finding-id> --output yaml
```

Command syntax errors are emitted as structured `invalid_input` documents on stderr. Help, version,
and generated completion scripts remain conventional plaintext terminal output.

List commands automatically follow Wiz cursors up to `--limit`, accept `--page-size` and `--cursor`,
and return continuation state in `meta.next_cursor`. `--max-pages` bounds API calls even if a server
returns pathological empty pages. Specific filter flags take precedence over the advanced `--filter`
JSON object.

Raw GraphQL supports inline queries, files, or stdin (`--query-file -`). Documents are parsed before
authentication; mutations and subscriptions are rejected even when hidden beside a query. Multiple
operations require `--operation-name`. `--allow-partial` preserves partial GraphQL data and reports
errors in envelope metadata.

All network endpoints must use HTTPS. The client secret is accepted only through
`WIZ_CLIENT_SECRET`, never a process-list-visible flag. The HTTP client disables redirects, enforces
time and response size limits, retries bounded transient failures, and never emits credentials in errors. The hidden
`--allow-insecure-http` switch exists solely for localhost integration tests.

Generate discovery and shell integration locally, without credentials:

```sh
wand agent schema
wand completions zsh
```

## Development

Mise owns all tooling and project tasks:

```sh
mise install
mise run check
mise run build
```

The same `mise run check` gate runs on Linux, macOS, and Windows in GitHub Actions and includes
formatting, Clippy with warnings denied, unit tests, and black-box HTTP/CLI integration tests.
Separate Mise tasks run dependency advisories and secret scanning. Workflow actions are pinned to
immutable commits.

The checked-in projections still need validation against a real Wiz tenant because the authoritative
schema is tenant-gated.

See [`docs/adr/0001-technology-stack.md`](docs/adr/0001-technology-stack.md).
