# Contributing to Fula Storage API

Thank you for your interest in contributing to Fula Storage! This document provides guidelines and information for contributors.

## Getting Started

### Prerequisites

- Rust 1.83 or later
- Docker and Docker Compose (for running IPFS locally)
- Git

### Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/functionland/fula-api
   cd fula-api
   ```

2. **Start the development stack**
   ```bash
   docker-compose up -d ipfs cluster
   ```

3. **Build the project**
   ```bash
   cargo build
   ```

4. **Run tests**
   ```bash
   cargo test
   ```

5. **Run the gateway locally**
   ```bash
   cargo run --package fula-cli -- --no-auth --debug
   ```

## Project Structure

```
fula-api/
├── crates/
│   ├── fula-crypto/      # Cryptographic primitives
│   ├── fula-blockstore/  # IPFS block storage
│   ├── fula-core/        # Storage engine
│   ├── fula-cli/         # Gateway server
│   └── fula-client/      # Client SDK
├── examples/             # Usage examples
├── docs/                 # Documentation
└── tests/                # Integration tests
```

## Coding Standards

### Rust Style

- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Run `cargo fmt` before committing
- Run `cargo clippy` and address warnings
- Add documentation for public APIs

### Commit Messages

Use conventional commit format:

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Test changes
- `chore`: Build/tooling changes

Examples:
```
feat(core): add Prolly Tree diff algorithm
fix(gateway): handle multipart upload timeout
docs(readme): add S3 compatibility examples
```

### Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass: `cargo test`
6. Run lints: `cargo fmt && cargo clippy`
7. Push and create a Pull Request

### Testing

- Write unit tests for all new functions
- Add integration tests for API endpoints
- Test with real IPFS nodes when possible
- Aim for >80% code coverage

```bash
# Run all tests
cargo test

# Run with logging
RUST_LOG=debug cargo test

# Run specific test
cargo test test_prolly_tree

# Run benchmarks
cargo bench
```

## Architecture Guidelines

### Layer Separation

- `fula-crypto`: Pure cryptographic functions, no I/O
- `fula-blockstore`: Block-level operations, IPFS interaction
- `fula-core`: Business logic, bucket/object management
- `fula-cli`: HTTP layer, S3 API translation

### Error Handling

- Use `thiserror` for error types
- Propagate errors with context
- Map internal errors to S3 error codes at the gateway layer

### Async Considerations

- Use `tokio` for async runtime
- Prefer `async_trait` for async trait methods
- Avoid blocking operations in async contexts

## Documentation

- Add rustdoc comments for public APIs
- Include examples in documentation
- Update README.md for user-facing changes
- Update OpenAPI spec for API changes

## Security

### Reporting Vulnerabilities

Please report security vulnerabilities privately to security@fx.land. Do not create public issues for security problems.

### Security Best Practices

- Never log sensitive data (keys, tokens)
- Validate all user input
- Use constant-time comparison for secrets
- Follow cryptographic best practices

## Getting Help

- Open a GitHub issue for bugs or features
- Join our Discord for discussions
- Check existing issues before creating new ones

## License

By contributing, you agree that your contributions will be licensed under the MIT/Apache-2.0 dual license.
