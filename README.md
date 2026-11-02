# vuln-check — MCP server

**Dependency vulnerability lookup as one MCP call.** Powered by [Google OSV.dev](https://osv.dev) (Open Source Vulnerabilities): the unified database of CVE/GHSA/PYSEC/GO/... advisories across PyPI, npm, Go, Maven, crates.io, RubyGems, Hex, NuGet, Debian and more.

Zero configuration — **no API key, no signup, no install beyond `npx`**.

## Why

Every coding agent that touches dependencies needs to answer "is this version vulnerable, and what do I upgrade to?". `vuln-check` gives your agent direct, structured access to OSV — advisory ids, CVE aliases, CVSS vectors, and the exact fixed versions — without pasting lockfiles into web UIs or burning a rate-limited commercial API key.

## Tools

| Tool | What it answers |
|---|---|
| `osv_query_package` | "Is `requests 2.19.0` on PyPI vulnerable?" → advisories, CVEs, fixed versions |
| `osv_batch_scan` | "Audit my whole pinned dependency list" → up to **50 dependencies in one call** |
| `osv_vuln_detail` | "Give me everything on `GHSA-9hjg-9r4m-mvj7`" → CVSS vectors, ranges, references |
| `osv_query_commit` | "My Go module is pinned to commit `abc123…` — any vulns?" |

## Connect

Claude Desktop / Cursor / any MCP client — one JSON block:

```json
{
  "mcpServers": {
    "vuln-check": {
      "command": "npx",
      "args": ["-y", "@hux_xl/vuln-check"]
    }
  }
}
```

Or run it directly:

```bash
npx -y @hux_xl/vuln-check
```

## Example

```json
→ tools/call osv_batch_scan
  { "queries": [
      { "ecosystem": "PyPI", "package": "requests", "version": "2.19.0" },
      { "ecosystem": "npm", "package": "@babel/traverse", "version": "7.22.5" }
  ]}

← {
  "scanned": 2,
  "vulnerable_dependencies": 2,
  "summary": "2/2 dependencies have open advisories",
  "results": [
    { "dependency": "requests", "ecosystem": "PyPI",
      "vulnerable": true,
      "vulnerabilities": [
        { "id": "GHSA-9hjg-9r4m-mvj7",
          "aliases": ["CVE-2024-47081", "PYSEC-2026-1872"],
          "summary": "Requests vulnerable to .netrc credentials leak via malicious URLs",
          "severity_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
          "fixed_versions": ["2.32.4"] } ] },
    { "dependency": "@babel/traverse", "ecosystem": "npm",
      "vulnerable": true,
      "vulnerabilities": [
        { "id": "GHSA-67hx-6x53-jw92",
          "aliases": ["CVE-2023-45133"],
          "summary": "Babel vulnerable to arbitrary code execution when compiling specifically crafted malicious code",
          "fixed_versions": ["7.23.2", "8.0.0-alpha.4"] } ] }
  ]
}
```

## Network and permissions

- **Hosts fetched:** `api.osv.dev` only (HTTPS POST to `/v1/query` and `/v1/querybatch`, HTTPS GET to `/v1/vulns/{id}`). No other network access, ever.
- **Purpose:** each call forwards the *package coordinates you supply in the query* (ecosystem, name, version/commit) to OSV to receive matching advisories back. This is the documented public interface of OSV (https://google.github.io/osv.dev/), an open-data project.
- **No secrets:** no API key, token, or environment credential is read, sent, or stored.
- **Outbound data:** query payloads only (package names/versions). No local files, environment, or working-directory data is transmitted.
- **Doc-only URL** (not fetched): https://osv.dev — human-readable project site.

## Privacy & data handling

OSV.dev is Google-run open-source infrastructure; like any public web API its operator logs requests (see https://osv.dev/terms). The data you expose is only what you type into a query — package names and versions you are checking.

## Limits

- `osv_batch_scan` accepts up to 50 entries per call (OSV batch endpoint).
- 15 s timeout per OSV request; on upstream failure the tool returns a clean `isError` payload rather than hanging.

## License

MIT © NZ1Labs
