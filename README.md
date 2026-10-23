# PkgGuard

Dependency vulnerability and malicious-package scanner for AI coding agents (MCP server + x402 API). Safety check only.

PkgGuard checks a `package.json`, `package-lock.json`, `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `go.mod`, `Cargo.lock` or `composer.lock` (or a plain package list) against [OSV.dev](https://osv.dev) for **known vulnerabilities** (CVE / GHSA / PYSEC / GO / RUSTSEC ids, severity, CVSS, fixed-in versions) and **confirmed-malicious packages**. Manifests are parsed locally; only `{ecosystem, name, version}` triples leave your machine.

- **Hosted remote MCP:** `https://api.youraitools.co/pkgguard/mcp` (Streamable HTTP)
- **Free tier:** 30 full-result calls/day per IP (up to 100 packages per scan) on the remote MCP endpoint, then $0.003 USDC per scan (up to 500 packages) or $0.001 per single package over [x402](https://x402.org), in USDC on Base, Polygon, Arbitrum One or Solana. No account or API key.
- **Hosted API:** https://api.youraitools.co/pkgguard (`POST /v1/scan` ($0.003, up to 500 packages), `GET|POST /v1/package` ($0.001), free `GET|POST /v1/preview` (verdict + counts, up to 25 packages, 10/min per IP))
- **Local stdio MCP server:** this repo. Starts with no key, no account and no npm registry package.
- **MCP Registry:** `co.youraitools/pkgguard`
- **License:** MIT

## Use the hosted server (no install)

Claude Code:

```bash
claude mcp add --transport http pkgguard https://api.youraitools.co/pkgguard/mcp
```

Claude Desktop: Settings > Connectors > Add custom connector with the URL above, or in `claude_desktop_config.json`:

```json
{ "mcpServers": { "pkgguard": { "command": "npx", "args": ["-y", "mcp-remote", "https://api.youraitools.co/pkgguard/mcp"] } } }
```

Cursor (`~/.cursor/mcp.json`), or one click: [Add to Cursor](cursor://anysphere.cursor-deeplink/mcp/install?name=pkgguard&config=eyJ1cmwiOiJodHRwczovL2FwaS55b3VyYWl0b29scy5jby9wa2dndWFyZC9tY3AifQ%3D%3D)

```json
{ "mcpServers": { "pkgguard": { "url": "https://api.youraitools.co/pkgguard/mcp" } } }
```

Each free result includes an `upgrade` field with the calls left today. Past the daily limit the tool returns a `payment_required` (402) result with the paid x402 URL.

## Self-host: run from source (no npm registry)

Requires Node.js 20+ (or Docker). The server has no runtime dependencies.

```bash
git clone https://github.com/Duffey234/pkgguard.git
cd pkgguard
npm ci --omit=dev
node src/mcp-stdio.js        # stdio MCP server (newline-delimited JSON-RPC 2.0)
```

No git? Download the source tarball from the mirror instead: `curl -sL https://agentgate-source.pages.dev/x402-pkgguard/x402-pkgguard.tar.gz | tar xz`.

MCP client config (use the absolute path of your checkout):

```json
{ "mcpServers": { "pkgguard": { "command": "node", "args": ["/absolute/path/to/pkgguard/src/mcp-stdio.js"] } } }
```

Claude Code: `claude mcp add pkgguard -- node /absolute/path/to/pkgguard/src/mcp-stdio.js`

Tools `scan_dependencies` (manifest contents, a local file path, or a package list) and `check_package` (one package version). With no key the server returns the free hosted preview (verdict and counts, up to 25 packages, 10 calls/min per IP). It needs outbound HTTPS to `api.youraitools.co`.

### Docker

```bash
docker build -t pkgguard-mcp .
docker run -i --rm pkgguard-mcp
```

```json
{ "mcpServers": { "pkgguard": { "command": "docker", "args": ["run", "-i", "--rm", "pkgguard-mcp"] } } }
```

### Paid mode (optional)

For full results in the local server, set `PKGGUARD_X402_PRIVATE_KEY` (or `X402_PRIVATE_KEY`) to the private key of a dedicated, low-balance Base wallet holding a few cents of USDC, and install the x402 client packages in your checkout:

```bash
npm install @x402/fetch @x402/evm viem
```

```json
{ "mcpServers": { "pkgguard": { "command": "node", "args": ["/absolute/path/to/pkgguard/src/mcp-stdio.js"],
  "env": { "PKGGUARD_X402_PRIVATE_KEY": "0x<key of a wallet with a few cents of USDC on Base>" } } } }
```

The server then pays the hosted API per call over x402 (Base USDC only, capped per payment, only to the published pay-to address). The key stays in your MCP client config and is only used to sign x402 payments. Without a key, nothing is paid.

## Test

```bash
npm test        # starts the stdio server with no key and checks initialize + tools/list
```

## Full source

The complete hosted service (Cloudflare Worker, x402 v2 + v1, remote MCP) is on the source mirror: https://agentgate-source.pages.dev/x402-pkgguard/

Built by [YourAITools](https://youraitools.co). Informational tooling, safety check only; no warranty.
