# @functionland/fula-mcp

Local **MCP (Model Context Protocol)** stdio server for [Fula](https://github.com/functionland/fula-api)
decentralized storage. It lets an AI assistant (Claude Desktop, Claude Code,
Codex CLI, Gemini CLI, …) store and retrieve files in FxFiles' end-to-end
encrypted format — running **build-free** on your machine.

```bash
npx @functionland/fula-mcp
```

The first run downloads the prebuilt `fula-mcp` binary for your platform from the
matching [GitHub Release](https://github.com/functionland/fula-api/releases),
verifies it, and caches it. Subsequent runs use the cache (no network).

## Use it as an MCP server

The server speaks MCP over **stdio**. Point your AI client at it. The per-session
capability bundle is injected via the `FULA_MCP_CAPABILITY` environment variable
(minted by the component that pairs your AI with your Fula account); this wrapper
forwards your environment and stdio to the binary unchanged.

### Claude Desktop / Claude Code (`mcpServers` config)

```jsonc
{
  "mcpServers": {
    "fula": {
      "command": "npx",
      "args": ["-y", "@functionland/fula-mcp"],
      "env": { "FULA_MCP_CAPABILITY": "<your connection bundle JSON>" }
    }
  }
}
```

> Tip: run `npx -y @functionland/fula-mcp` once in a terminal first to warm the
> binary cache, so the client doesn't time out waiting for the first download.

## Supported platforms

| OS      | Arch  | Rust target                  |
| ------- | ----- | ---------------------------- |
| Windows | x64   | `x86_64-pc-windows-msvc`     |
| Linux   | x64   | `x86_64-unknown-linux-gnu`   |
| Linux   | arm64 | `aarch64-unknown-linux-gnu`  |
| macOS   | x64   | `x86_64-apple-darwin`        |
| macOS   | arm64 | `aarch64-apple-darwin`       |

## Security: how the binary is trusted

This wrapper downloads a native binary and runs it. The trust model:

- The binary is fetched from the GitHub Release whose tag matches **this package's
  version** (`fula-mcp-v{version}`).
- Its SHA-256 is verified against a **`checksums.json` bundled inside this npm
  package** — written at release time, in the same CI run that built the binary.
- The npm package itself is published via **OIDC trusted publishing with
  provenance** (no long-lived token), so the package — and therefore the bundled
  checksum — is the trust root.
- If the Release asset is ever swapped, its hash won't match the bundled
  checksum and the wrapper **refuses to execute it**. The binary is re-verified
  immediately before every launch.

Residual trust: this does not (and cannot) defend against a compromise of the CI
run that produces both the binary and the bundled checksum. Tags are protected
and the publish runs in a restricted environment to mitigate that.

### Environment variables

| Variable               | Effect                                                             |
| ---------------------- | ----------------------------------------------------------------- |
| `FULA_MCP_CAPABILITY`  | (passed through) the per-session capability bundle for the server |
| `FULA_MCP_JWT`         | (passed through) optional out-of-band JWT override                |
| `RUST_LOG`             | (passed through) binary log level (logs go to stderr)             |
| `FULA_MCP_CACHE_DIR`   | override the binary cache directory                               |

## License

MIT OR Apache-2.0
