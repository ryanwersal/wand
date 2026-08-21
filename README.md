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
wand issues get <issue-id>
wand vulnerabilities list
wand vulnerabilities get <finding-id>
wand agent schema
```

Run `wand help` or `wand <command> --help` for the complete command reference.

## Development

```sh
mise install
mise run check
mise run build
```

## License

[Apache-2.0](LICENSE)
