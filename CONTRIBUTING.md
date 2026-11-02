# Contributing to pingtxt-push-relay

Thanks for helping. The push relay is a small companion service of [pingtxt](https://github.com/federico-it/pingtxt),
so most features and bug reports belong there: open them in
[pingtxt's issues](https://github.com/federico-it/pingtxt/issues) unless the problem is clearly in this
service.

- **Security issue?** Do not open a public issue. Follow [SECURITY.md](SECURITY.md).
- For anything bigger than a small fix, open an issue first and agree on the approach.
- Remove tokens, secrets and IPs you don't want public from logs and screenshots.
- Never commit credentials (Firebase service account keys, `RELAY_SECRET`, `.env`).

## Development

You need **Go** (the version in [go.mod](go.mod)). Docker is optional.

```sh
go test -race ./...
RELAY_SECRET=$(openssl rand -base64 48) go run ./cmd/pingtxt-push-relay
docker build -t pingtxt-push-relay .
```

## Pull requests

- Keep each pull request to one change, with tests for new behavior.
- Run `gofmt -l .`, `go vet ./...` and `go test -race ./...` before pushing: CI runs the same checks
  and builds the Docker image.
- Update README.md, and docs/openapi.json when a route changes (a test checks it matches the server).
- By contributing you agree that your work is licensed under the [AGPL-3.0](LICENSE), like the rest of
  the project. The [pingtxt code of conduct](https://github.com/federico-it/pingtxt/blob/main/CODE_OF_CONDUCT.md)
  applies here too.
