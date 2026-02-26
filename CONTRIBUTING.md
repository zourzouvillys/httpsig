# Contributing to httpsig

Thanks for your interest in contributing!

## Getting Started

This is a multi-language monorepo. Each language lives in its own directory with its own build system:

| Language | Directory | Build |
|---|---|---|
| Go | `golang/` | `go test ./...` |
| TypeScript | `typescript/` | `npm test` |
| Java | `java/` | `./gradlew check` |
| Swift | `swift/` | `swift test` |
| Kotlin | `kotlin/` | `./gradlew check` |

## Development

### Prerequisites

Install the toolchain for whichever language you want to work on. You don't need all of them.

### Shared Test Vectors

The `testdata/` directory contains shared test vectors derived from RFC 9421 Appendix B. All language implementations load these vectors and must pass them. If you modify the vectors, all languages need to be updated.

### Running Tests

```bash
# Single language
make test-go
make test-ts
make test-java
make test-swift
make test-kotlin

# All languages
make test-all
```

## Pull Requests

1. Fork the repo and create a branch from `main`.
2. Add tests for any new functionality.
3. Ensure all existing tests pass for the language(s) you modified.
4. Keep PRs focused. One feature or fix per PR.
5. Update documentation if you changed public API.

## Code Style

Follow the idiomatic style for each language. The CI enforces linting:

- **Go**: `go vet` + `staticcheck`
- **TypeScript**: `eslint`
- **Java/Kotlin**: Gradle `check` task
- **Swift**: Swift compiler warnings

## Reporting Issues

Use GitHub Issues. Include:
- Which language implementation
- Version / commit
- Minimal reproduction
- Expected vs actual behavior

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
