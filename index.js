#!/usr/bin/env node
/**
 * @hux_xl/vuln-check — MCP stdio server
 *
 * Dependency vulnerability lookup backed by Google Open Source Vulneraries
 * (OSV.dev). Zero API key, zero dependencies, free endpoint.
 *
 * Tools:
 *   osv_query_package  — CVEs for one package+version in one ecosystem
 *   osv_batch_scan     — one-call scan of up to 50 dependencies
 *   osv_vuln_detail    — full advisory detail for one OSV id (GHSA/CVE/PYSEC)
 *   osv_query_commit   — CVEs touching a specific git commit
 *
 * Network: HTTPS POST/GET to api.osv.dev only (see README "Network and
 * permissions"). No credentials are sent or stored; queries send only the
 * package coordinates the caller supplies.
 *
 * Protocol: MCP over stdio (JSON-RPC 2.0, one message per line).
 */

const SERVER_NAME = 'nz1labs-vuln-check';
const SERVER_VERSION = '1.0.0';
const PROTOCOL_VERSION = '2024-11-05';
const OSV_QUERY_URL = 'https://api.osv.dev/v1/query';
const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch';
const OSV_VULN_URL = 'https://api.osv.dev/v1/vulns/';
const DETAIL_ENRICH_CAP = 24; // max advisories fully expanded per batch scan
const DETAIL_CONCURRENCY = 8;
const FETCH_TIMEOUT_MS = 15000;
const USER_AGENT =
  'nz1labs-vuln-check/1.0.0 (+https://github.com/isoloman275-wq/vuln-check)';

// Ecosystem names as OSV spells them.
const ECOSYSTEMS = [
  'PyPI', 'npm', 'Go', 'Maven', 'crates.io', 'RubyGems', 'Hex', 'Hackage',
  'Pub', 'NuGet', 'CPAN', 'GitHub Actions', 'Linux', 'Debian:', 'Alpine:',
  'Ubuntu:', 'ROS:', 'Android', 'SwiftURL',
];

const TOOLS = [
  {
    name: 'osv_query_package',
    description:
      'Find known vulnerabilities (CVE/GHSA advisories) for one dependency at a specific version via OSV.dev. Returns advisory ids, CVE aliases, summaries, CVSS vectors and fixed versions. Ecosystem examples: PyPI, npm, Go, Maven, crates.io, RubyGems, Hex, NuGet, GitHub Actions.',
    inputSchema: {
      type: 'object',
      properties: {
        ecosystem: {
          type: 'string',
          description:
            'Package ecosystem exactly as OSV names it (e.g. "PyPI", "npm", "Go", "Maven", "crates.io").',
        },
        package: {
          type: 'string',
          description: 'Package name, e.g. "requests" or "@babel/traverse".',
        },
        version: {
          type: 'string',
          description:
            'Installed version, e.g. "2.19.0". Optional: omit to list all advisories ever filed for the package.',
        },
      },
      required: ['ecosystem', 'package'],
    },
  },
  {
    name: 'osv_batch_scan',
    description:
      'Scan up to 50 pinned dependencies in ONE OSV batch query — ideal for auditing a requirements.txt, go.mod, Cargo.lock or package.json dependency tree in a single call. Returns per-dependency vulnerability verdicts.',
    inputSchema: {
      type: 'object',
      properties: {
        queries: {
          type: 'array',
          maxItems: 50,
          items: {
            type: 'object',
            properties: {
              ecosystem: { type: 'string' },
              package: { type: 'string' },
              version: { type: 'string' },
            },
            required: ['ecosystem', 'package'],
          },
          description:
            'Array of {ecosystem, package, version} entries (max 50).',
        },
      },
      required: ['queries'],
    },
  },
  {
    name: 'osv_vuln_detail',
    description:
      'Fetch the full advisory for one OSV id (e.g. GHSA-xxxx, CVE id, PYSEC-..., GO-...) — CVSS vectors, affected version ranges, fixed versions, references, and ecosystem notes.',
    inputSchema: {
      type: 'object',
      properties: {
        id: {
          type: 'string',
          description: 'OSV advisory id, e.g. "GHSA-hjs4-c52w-c4f7".',
        },
      },
      required: ['id'],
    },
  },
  {
    name: 'osv_query_commit',
    description:
      'Find vulnerabilities that touch a specific git commit (full 40-char SHA) in any tracked ecosystem — useful when you know the exact commit a dependency is pinned to (go pseudo-versions, lockfile commits).',
    inputSchema: {
      type: 'object',
      properties: {
        commit: {
          type: 'string',
          description: 'Full 40-character git commit SHA.',
        },
      },
      required: ['commit'],
    },
  },
];

async function osvPost(url, bodyObj) {
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'user-agent': USER_AGENT,
    },
    body: JSON.stringify(bodyObj),
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`OSV query HTTP ${res.status}: ${body.slice(0, 200) || res.statusText}`);
  }
  return res.json();
}

async function osvGetVuln(id) {
  const url = OSV_VULN_URL + encodeURIComponent(id);
  const res = await fetch(url, {
    headers: { 'user-agent': USER_AGENT, accept: 'application/json' },
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`OSV advisory HTTP ${res.status}: ${body.slice(0, 200) || res.statusText}`);
  }
  return res.json();
}

function fixedVersions(vuln) {
  const fixed = new Set();
  for (const a of vuln.affected ?? []) {
    for (const r of a.ranges ?? []) {
      for (const e of r.events ?? []) {
        if (e.fixed) fixed.add(e.fixed);
      }
    }
  }
  return [...fixed].slice(0, 10);
}

function maxCvss(vuln) {
  let best = null;
  for (const s of vuln.severity ?? []) {
    if (typeof s.score === 'string' && s.score.startsWith('CVSS')) {
      if (!best || s.score.startsWith('CVSS:3') || !best.startsWith('CVSS:3')) {
        if (!best) best = s.score;
        if (s.score.startsWith('CVSS:3')) best = s.score; // prefer v3/v4
      }
    }
  }
  return best;
}

function summarize(vuln) {
  if (!vuln || typeof vuln !== 'object') return vuln;
  return {
    id: vuln.id,
    aliases: vuln.aliases ?? [],
    summary: vuln.summary ?? vuln.details?.slice(0, 200) ?? '',
    severity_vector: maxCvss(vuln),
    fixed_versions: fixedVersions(vuln),
    affected_ecosystems: [
      ...new Set((vuln.affected ?? []).map((a) => a.package?.ecosystem).filter(Boolean)),
    ],
  };
}

function ecosystemHint(ecosystem) {
  const e = String(ecosystem ?? '');
  if (ECOSYSTEMS.some((k) => e === k || e.startsWith(k))) return null;
  return `"${e}" is not a recognised OSV ecosystem name (known: ${ECOSYSTEMS.join(', ')}); querying it anyway`;
}

async function callOsvQueryPackage(args) {
  const q = { package: { name: String(args.package), ecosystem: String(args.ecosystem) } };
  if (args.version) q.version = String(args.version);
  const hint = ecosystemHint(args.ecosystem);
  const data = await osvPost(OSV_QUERY_URL, q);
  const vulns = (data.vulns ?? []).map(summarize);
  return {
    query: { ecosystem: q.package.ecosystem, package: q.package.name, version: q.version ?? null },
    vulnerable: vulns.length > 0,
    vulnerability_count: vulns.length,
    vulnerabilities: vulns,
    note: hint ?? undefined,
  };
}

async function callOsvBatchScan(args) {
  const list = Array.isArray(args.queries) ? args.queries.slice(0, 50) : [];
  if (list.length === 0) throw new Error('queries must be a non-empty array of {ecosystem, package, version}');
  const queries = list.map((p) => {
    const q = { package: { name: String(p.package), ecosystem: String(p.ecosystem) } };
    if (p.version) q.version = String(p.version);
    return q;
  });
  // 1) cheap id stubs in one round-trip
  const data = await osvPost(OSV_BATCH_URL, { queries });
  const perDep = (data.results ?? []).map((r, i) => ({
    dependency: queries[i]?.package?.name ?? `query#${i}`,
    ecosystem: queries[i]?.package?.ecosystem ?? null,
    stubs: r.vulns ?? [],
  }));
  // 2) expand advisories (deduped, capped, concurrency-limited)
  const allIds = [...new Set(perDep.flatMap((d) => d.stubs.map((s) => s.id)))];
  const enrichIds = allIds.slice(0, DETAIL_ENRICH_CAP);
  const detailById = new Map();
  for (let i = 0; i < enrichIds.length; i += DETAIL_CONCURRENCY) {
    const chunk = enrichIds.slice(i, i + DETAIL_CONCURRENCY);
    const settled = await Promise.allSettled(chunk.map((id) => osvGetVuln(id)));
    settled.forEach((s, j) => {
      if (s.status === 'fulfilled') detailById.set(chunk[j], summarize(s.value));
      else detailById.set(chunk[j], { id: chunk[j], detail_error: s.reason?.message ?? String(s.reason) });
    });
  }
  const results = perDep.map((d) => ({
    dependency: d.dependency,
    ecosystem: d.ecosystem,
    vulnerable: d.stubs.length > 0,
    vulnerabilities: d.stubs.map((s) => detailById.get(s.id) ?? { id: s.id, detail: 'not expanded (cap reached)' }),
  }));
  const flagged = results.filter((r) => r.vulnerable);
  return {
    scanned: results.length,
    vulnerable_dependencies: flagged.length,
    advisories_expanded: detailById.size,
    summary:
      flagged.length === 0
        ? `all ${results.length} dependencies clean against OSV`
        : `${flagged.length}/${results.length} dependencies have open advisories`,
    results,
  };
}

async function callOsvVulnDetail(args) {
  const id = String(args.id);
  const v = await osvGetVuln(id);
  const detail = summarize(v);
  detail.details = (v.details ?? '').slice(0, 2000);
  detail.references = (v.references ?? []).map((r) => r.url).slice(0, 15);
  detail.modified = v.modified ?? null;
  detail.published = v.published ?? null;
  return detail;
}

async function callOsvQueryCommit(args) {
  const commit = String(args.commit);
  if (!/^[0-9a-fA-F]{40}$/.test(commit))
    throw new Error('commit must be a full 40-char git SHA');
  const data = await osvPost(OSV_QUERY_URL, { commit });
  const vulns = (data.vulns ?? []).map(summarize);
  return {
    commit,
    vulnerable: vulns.length > 0,
    vulnerability_count: vulns.length,
    vulnerabilities: vulns,
  };
}

const TOOL_IMPL = {
  osv_query_package: callOsvQueryPackage,
  osv_batch_scan: callOsvBatchScan,
  osv_vuln_detail: callOsvVulnDetail,
  osv_query_commit: callOsvQueryCommit,
};

async function handleRpc(body) {
  const method = body.method ?? '';
  const id = body.id;
  const params = body.params ?? {};

  if (method === 'initialize') {
    return {
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: { tools: {} },
        serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
      },
    };
  }
  if (method === 'notifications/initialized') return null;
  if (method === 'ping') return { jsonrpc: '2.0', id, result: {} };
  if (method === 'tools/list') {
    return { jsonrpc: '2.0', id, result: { tools: TOOLS } };
  }
  if (method === 'tools/call') {
    const name = params.name ?? '';
    const args = params.arguments ?? {};
    const impl = TOOL_IMPL[name];
    if (!impl) {
      return {
        jsonrpc: '2.0',
        id,
        error: { code: -32601, message: `unknown tool: ${name}` },
      };
    }
    try {
      const result = await impl(args);
      return {
        jsonrpc: '2.0',
        id,
        result: {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
          isError: false,
        },
      };
    } catch (err) {
      return {
        jsonrpc: '2.0',
        id,
        result: {
          content: [
            { type: 'text', text: `osv lookup failed: ${err.message}` },
          ],
          isError: true,
        },
      };
    }
  }
  return {
    jsonrpc: '2.0',
    id,
    error: { code: -32601, message: `unknown method: ${method}` },
  };
}

import { createInterface } from 'node:readline';
const rl = createInterface({ input: process.stdin });
rl.on('line', (line) => {
  const raw = line.trim();
  if (!raw) return;
  let body;
  try {
    body = JSON.parse(raw);
  } catch {
    process.stdout.write(
      JSON.stringify({
        jsonrpc: '2.0',
        id: null,
        error: { code: -32700, message: 'parse error' },
      }) + '\n'
    );
    return;
  }
  handleRpc(body)
    .then((resp) => {
      if (resp !== null) process.stdout.write(JSON.stringify(resp) + '\n');
    })
    .catch((err) => {
      process.stdout.write(
        JSON.stringify({
          jsonrpc: '2.0',
          id: body.id ?? null,
          error: { code: -32603, message: String(err?.message ?? err) },
        }) + '\n'
      );
    });
});

process.stderr.write(
  `[${SERVER_NAME}] v${SERVER_VERSION} — MCP stdio server ready (osv.dev)\n`
);
