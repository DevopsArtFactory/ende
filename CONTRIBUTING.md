# Contributing to Ende

Thanks for considering a contribution.

## Development setup
1. Install Go (see `go.mod` for version).
2. Clone the repository.
3. Run tests:
   ```bash
   go test ./...
   ```

## Build
```bash
make build
make build-all
```

Docker-based build/test is also available:
```bash
make vendor
make docker-test
make docker-build-all
```

## Pull request guidelines
- Keep PRs focused and small.
- Add or update tests for behavior changes.
- Update docs when CLI behavior changes.
- Use clear commit messages.

## Security-sensitive changes
If your change affects crypto, key handling, or trust decisions, include:
- threat model impact,
- migration/compatibility considerations,
- validation strategy (tests/manual steps).
