# Wand

Wand is a read-only CLI for retrieving Wiz issues and vulnerability findings.

## Configuration

```sh
export WIZ_API_ENDPOINT='https://api.us1.app.wiz.io/graphql'
export WIZ_CLIENT_ID='...'
export WIZ_CLIENT_SECRET='...'
```

## Usage

```sh
wand auth check
wand issues list
wand issues filters
wand issues get <issue-id>
wand vulnerabilities list
wand vulnerabilities filters
wand vulnerabilities get <finding-id>
wand agent schema
```

Run `wand help` or `wand <command> --help` for the complete command reference.

List commands expose named filters for the Wiz fields most useful in investigation workflows.
Multi-value flags accept comma-separated values and can also be repeated. Boolean flags accept
both `--has-exploit` (true) and `--has-exploit=false`. Time filters use RFC 3339 timestamps and
score filters accept values from 0 through 10. Container registry, repository, and base-image values
may be either human-readable names/paths or Wiz UUIDs; Wand resolves names before querying
vulnerability findings. Vulnerability project values likewise accept exact names, slugs, or UUIDs;
resolving a name or slug requires the optional Wiz `read:projects` scope, while UUIDs do not.

```sh
wand vulnerabilities list \
  --container-repository public.ecr.aws/datadog/agent \
  --has-exploit \
  --status OPEN \
  --severity CRITICAL,HIGH \
  --updated-after 2026-08-01T00:00:00Z

wand issues list \
  --search datadog \
  --has-remediation true \
  --created-after 2026-08-01T00:00:00Z
```

Filter discovery is local and does not require Wiz credentials. Pass a search term to narrow the
catalog, and select table output for interactive use:

```sh
wand --output table vulnerabilities filters container
wand --output table vulnerabilities filters runtime
wand issues filters remediation
```

JSON discovery uses Wand's normal response envelope; its `data` field is an array of filters with
`flag`, `category`, `description`, `graphql_field`, `operation`, and `possible_values` fields.
`--filter` remains available as an advanced escape hatch
for tenant-specific or newly introduced Wiz filters; named flags take precedence when both specify
the same field.

## Development

```sh
mise install
mise run check
mise run build
```

## License

[Apache-2.0](LICENSE)
