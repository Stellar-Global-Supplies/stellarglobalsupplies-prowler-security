/**
 * Prowler Security Dashboard — Cloudflare Worker API
 *
 * Endpoints:
 *   POST /ingest           — receive findings from GitHub Actions
 *   GET  /api/score        — posture score + severity counts
 *   GET  /api/findings     — paginated findings (ALL statuses by default)
 *   GET  /api/checks       — all executed checks with pass/fail counts per check_id
 *   GET  /api/services     — service-level breakdown
 *   GET  /api/graph        — nodes + edges for D3 attack graph
 *   GET  /api/history      — scan history for trend chart
 *   GET  /api/compliance   — compliance framework coverage
 */

export interface Env {
  DB: D1Database;
  INGEST_TOKEN: SecretsStoreSecret;
}

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...CORS },
  });
}

function unauthorized() {
  return json({ error: "Unauthorized" }, 401);
}

async function authOk(req: Request, env: Env): Promise<boolean> {
  const header = req.headers.get("Authorization") ?? "";
  const token = await env.INGEST_TOKEN.get();
  return header === `Bearer ${token}`;
}

// ── Ingest ──────────────────────────────────────────────────────────────────
async function handleIngest(req: Request, env: Env) {
  if (!(await authOk(req, env))) return unauthorized();

  let body: {
    scan_run: Record<string, unknown>;
    findings: Record<string, unknown>[];
    resources: Record<string, unknown>[];
    edges: Record<string, unknown>[];
  };

  try {
    body = await req.json();
  } catch {
    return json({ error: "Invalid JSON body" }, 400);
  }

  const { scan_run = {}, findings = [], resources = [], edges = [] } = body;

  // Insert scan run (only on first batch — when full scan metadata is present)
  if (scan_run.provider && scan_run.scanned_at) {
    await env.DB.prepare(
      `INSERT OR REPLACE INTO scan_runs
       (id, provider, scanned_at, checks_executed, total_checks, passed, failed, critical, high, medium, low, score)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`
    )
      .bind(
        scan_run.id, scan_run.provider, scan_run.scanned_at,
        scan_run.checks_executed ?? scan_run.total ?? 0,
        scan_run.total, scan_run.passed, scan_run.failed,
        scan_run.critical, scan_run.high, scan_run.medium, scan_run.low,
        scan_run.score
      )
      .run();
  }

  // Batch insert findings (D1 max 100 per batch)
  const CHUNK = 100;
  for (let i = 0; i < findings.length; i += CHUNK) {
    const chunk = findings.slice(i, i + CHUNK);
    const stmt = env.DB.prepare(
      `INSERT OR REPLACE INTO findings
       (id, scan_run_id, provider, service, check_id, check_title, status,
        severity, resource_uid, resource_name, resource_type, region,
        description, remediation, scanned_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
    );
    await env.DB.batch(
      chunk.map((f) =>
        stmt.bind(
          f.id, f.scan_run_id, f.provider, f.service, f.check_id,
          f.check_title, f.status, f.severity, f.resource_uid,
          f.resource_name, f.resource_type, f.region,
          f.description, f.remediation, f.scanned_at
        )
      )
    );
  }

  // Upsert resources
  for (let i = 0; i < resources.length; i += CHUNK) {
    const chunk = resources.slice(i, i + CHUNK);
    const stmt = env.DB.prepare(
      `INSERT OR REPLACE INTO resources
       (id, provider, service, resource_type, resource_uid, resource_name, region, risk_score)
       VALUES (?,?,?,?,?,?,?,?)`
    );
    await env.DB.batch(
      chunk.map((r) =>
        stmt.bind(
          r.id, r.provider, r.service, r.resource_type,
          r.resource_uid, r.resource_name, r.region, r.risk_score
        )
      )
    );
  }

  // Upsert graph edges
  if (edges.length > 0) {
    for (let i = 0; i < edges.length; i += CHUNK) {
      const chunk = edges.slice(i, i + CHUNK);
      const stmt = env.DB.prepare(
        `INSERT OR REPLACE INTO graph_edges
         (id, source_id, target_id, source_label, target_label, relationship, severity)
         VALUES (?,?,?,?,?,?,?)`
      );
      await env.DB.batch(
        chunk.map((e) =>
          stmt.bind(
            e.id, e.source_id, e.target_id,
            e.source_label, e.target_label,
            e.relationship, e.severity
          )
        )
      );
    }
  }

  return json({ ok: true, ingested: findings.length });
}

// ── Score ────────────────────────────────────────────────────────────────────
async function handleScore(env: Env) {
  const latest = await env.DB.prepare(
    `SELECT provider, score, checks_executed, total_checks, passed, failed,
            critical, high, medium, low, scanned_at
     FROM scan_runs
     ORDER BY scanned_at DESC
     LIMIT 20`
  ).all();

  const byProvider: Record<string, unknown> = {};
  const seen = new Set<string>();
  for (const row of latest.results) {
    const p = row.provider as string;
    if (!seen.has(p)) { seen.add(p); byProvider[p] = row; }
  }

  const totals = Object.values(byProvider).reduce(
    (acc: Record<string, number>, r: unknown) => {
      const row = r as Record<string, number>;
      acc.checks_executed += row.checks_executed ?? row.total_checks ?? 0;
      acc.total   += row.total_checks ?? 0;
      acc.passed  += row.passed  ?? 0;
      acc.failed  += row.failed  ?? 0;
      acc.critical += row.critical ?? 0;
      acc.high    += row.high    ?? 0;
      acc.medium  += row.medium  ?? 0;
      acc.low     += row.low     ?? 0;
      return acc;
    },
    { checks_executed: 0, total: 0, passed: 0, failed: 0, critical: 0, high: 0, medium: 0, low: 0 }
  );

  const score = totals.total > 0
    ? Math.round((totals.passed / totals.total) * 100)
    : 0;

  return json({ score, ...totals, by_provider: byProvider });
}

// ── Findings ─────────────────────────────────────────────────────────────────
// Returns ALL statuses by default (PASS + FAIL + MANUAL + MUTED)
async function handleFindings(url: URL, env: Env) {
  const severity = url.searchParams.get("severity") ?? "";
  const status   = url.searchParams.get("status")   ?? "";   // empty = ALL
  const provider = url.searchParams.get("provider") ?? "";
  const service  = url.searchParams.get("service")  ?? "";
  const search   = url.searchParams.get("q")        ?? "";
  const page     = parseInt(url.searchParams.get("page")  ?? "1");
  const limit    = Math.min(parseInt(url.searchParams.get("limit") ?? "50"), 200);
  const offset   = (page - 1) * limit;

  const conditions: string[] = [];
  const binds: (string | number)[] = [];

  if (severity) { conditions.push("severity = ?");  binds.push(severity); }
  if (status)   { conditions.push("status = ?");    binds.push(status); }
  if (provider) { conditions.push("provider = ?");  binds.push(provider); }
  if (service)  { conditions.push("service = ?");   binds.push(service); }
  if (search) {
    conditions.push("(check_title LIKE ? OR resource_name LIKE ? OR description LIKE ? OR check_id LIKE ?)");
    const q = `%${search}%`;
    binds.push(q, q, q, q);
  }

  const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";

  const [rows, countRow] = await Promise.all([
    env.DB.prepare(
      `SELECT id, provider, service, check_id, check_title, status, severity,
              resource_name, resource_type, region, description, remediation,
              scanned_at, resource_uid
       FROM findings ${where}
       ORDER BY
         CASE severity
           WHEN 'critical' THEN 1 WHEN 'high' THEN 2
           WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5
         END,
         CASE status WHEN 'FAIL' THEN 1 ELSE 2 END,
         scanned_at DESC
       LIMIT ? OFFSET ?`
    ).bind(...binds, limit, offset).all(),
    env.DB.prepare(`SELECT COUNT(*) as total FROM findings ${where}`)
      .bind(...binds).first<{ total: number }>(),
  ]);

  return json({
    findings: rows.results,
    total: countRow?.total ?? 0,
    page,
    limit,
  });
}

// ── Checks summary ────────────────────────────────────────────────────────────
// Returns one row per check_id showing pass/fail counts — powers the
// "All Checks" view that shows all 635 executed checks.
async function handleChecks(url: URL, env: Env) {
  const provider = url.searchParams.get("provider") ?? "";
  const service  = url.searchParams.get("service")  ?? "";
  const status   = url.searchParams.get("status")   ?? "";
  const severity = url.searchParams.get("severity") ?? "";
  const search   = url.searchParams.get("q")        ?? "";
  const page     = parseInt(url.searchParams.get("page")  ?? "1");
  const limit    = Math.min(parseInt(url.searchParams.get("limit") ?? "100"), 500);
  const offset   = (page - 1) * limit;

  const conditions: string[] = [];
  const binds: (string | number)[] = [];

  if (provider) { conditions.push("provider = ?");  binds.push(provider); }
  if (service)  { conditions.push("service = ?");   binds.push(service); }
  if (severity) { conditions.push("severity = ?");  binds.push(severity); }
  if (search) {
    conditions.push("(check_title LIKE ? OR check_id LIKE ?)");
    const q = `%${search}%`;
    binds.push(q, q);
  }

  // status filter applies to the outer having clause
  const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";

  let havingClause = "";
  if (status === "FAIL") havingClause = "HAVING failed_count > 0";
  else if (status === "PASS") havingClause = "HAVING failed_count = 0";

  const [rows, countRow] = await Promise.all([
    env.DB.prepare(
      `SELECT
         check_id, check_title, service, provider, severity,
         COUNT(*) as total_resources,
         SUM(CASE WHEN status = 'PASS' THEN 1 ELSE 0 END) as passed_count,
         SUM(CASE WHEN status = 'FAIL' THEN 1 ELSE 0 END) as failed_count,
         SUM(CASE WHEN status = 'MUTED' THEN 1 ELSE 0 END) as muted_count,
         MAX(scanned_at) as last_seen
       FROM findings ${where}
       GROUP BY check_id, check_title, service, provider, severity
       ${havingClause}
       ORDER BY
         CASE severity
           WHEN 'critical' THEN 1 WHEN 'high' THEN 2
           WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5
         END,
         failed_count DESC
       LIMIT ? OFFSET ?`
    ).bind(...binds, limit, offset).all(),
    env.DB.prepare(
      `SELECT COUNT(DISTINCT check_id) as total
       FROM findings ${where}`
    ).bind(...binds).first<{ total: number }>(),
  ]);

  return json({
    checks: rows.results,
    total: countRow?.total ?? 0,
    page,
    limit,
  });
}

// ── Services breakdown ────────────────────────────────────────────────────────
async function handleServices(url: URL, env: Env) {
  const provider = url.searchParams.get("provider") ?? "";
  const where = provider ? "WHERE provider = ?" : "";
  const binds = provider ? [provider] : [];

  const rows = await env.DB.prepare(
    `SELECT
       service, provider,
       COUNT(DISTINCT check_id) as check_count,
       COUNT(*) as resource_count,
       SUM(CASE WHEN status = 'FAIL' THEN 1 ELSE 0 END) as failed,
       SUM(CASE WHEN status = 'PASS' THEN 1 ELSE 0 END) as passed,
       MAX(CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) as max_sev_num
     FROM findings ${where}
     GROUP BY service, provider
     ORDER BY failed DESC, max_sev_num DESC`
  ).bind(...binds).all();

  return json({ services: rows.results });
}

// ── Compliance ────────────────────────────────────────────────────────────────
async function handleCompliance(env: Env) {
  // findings table doesn't store compliance frameworks directly, but
  // check_id prefixes map to frameworks (cis_, soc2_, etc.)
  // We surface a pass/fail breakdown by service as a proxy.
  const rows = await env.DB.prepare(
    `SELECT
       provider,
       severity,
       COUNT(DISTINCT check_id) as checks,
       SUM(CASE WHEN status = 'PASS' THEN 1 ELSE 0 END) as passed,
       SUM(CASE WHEN status = 'FAIL' THEN 1 ELSE 0 END) as failed,
       COUNT(*) as total
     FROM findings
     GROUP BY provider, severity
     ORDER BY provider,
       CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END`
  ).all();

  return json({ breakdown: rows.results });
}

// ── Graph ─────────────────────────────────────────────────────────────────────
// The graph is built from findings data: resources that fail the same check are
// connected (shared-check edge = blast radius), and failing resources are linked
// to severity hub nodes (risk concentration).  The endpoint is resilient — if
// the D1 resources table is missing/empty it returns empty arrays instead of
// crashing (previously returned HTTP 500 / error 1101).
interface GraphNode {
  id: string;
  label: string;
  provider: string;
  service: string;
  region: string;
  risk: number;
  findings: number;
  severity: string;
}

interface GraphEdge {
  source_id: string;
  target_id: string;
  source_label: string;
  target_label: string;
  relationship: string;
  severity: string;
}

async function handleGraph(env: Env) {
  const SEV = ["low", "low", "medium", "high", "critical"];

  try {
    // 1. Resources + their findings stats
    const resourceRows = await env.DB.prepare(
      `SELECT r.id, r.provider, r.service, r.resource_type,
              r.resource_name, r.region, r.risk_score,
              COUNT(f.id) as finding_count,
              SUM(CASE WHEN f.status='FAIL' THEN 1 ELSE 0 END) as failed_count,
              MAX(CASE f.severity
                WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0
              END) as max_severity
       FROM resources r
       LEFT JOIN findings f ON f.resource_uid = r.resource_uid
       GROUP BY r.id
       LIMIT 200`
    ).all();

    // 2. Resources grouped by failing check_id (for shared-check edges)
    const sharedCheckRows = await env.DB.prepare(
      `SELECT f.resource_uid, f.resource_name, f.check_id, f.check_title, f.severity
       FROM findings f
       WHERE f.status = 'FAIL'
       ORDER BY f.check_id, f.resource_uid`
    ).all();

    const nodes: GraphNode[] = (resourceRows.results ?? []).map((r) => ({
      id: String(r.id ?? ""),
      label: String(r.resource_name || r.service || ""),
      provider: String(r.provider ?? ""),
      service: String(r.service ?? ""),
      region: String(r.region ?? "global"),
      risk: Number(r.risk_score ?? 0),
      findings: Number(r.failed_count ?? 0),
      severity: SEV[Number(r.max_severity ?? 0)] ?? "low",
    }));

    // Build a set of resource ids that exist as nodes
    const nodeIds = new Set<string>(nodes.map((n) => n.id));

    const edges: GraphEdge[] = [];
    const seenEdges = new Set<string>();

    function addEdge(source: string, target: string, relationship: string, severity: string) {
      const key = `${source}|${target}|${relationship}`;
      if (seenEdges.has(key)) return;
      seenEdges.add(key);
      edges.push({
        source_id: source,
        target_id: target,
        source_label: source,
        target_label: target,
        relationship,
        severity: severity || "medium",
      });
    }

    // 3a. Shared-check edges: resources failing the same check are connected
    const byCheck = new Map<string, { uid: string; sev: string }[]>();
    for (const f of (sharedCheckRows.results ?? [])) {
      const uid = String(f.resource_uid ?? "");
      if (!uid || !nodeIds.has(uid)) continue;
      const checkId = String(f.check_id ?? "");
      if (!checkId) continue;
      if (!byCheck.has(checkId)) byCheck.set(checkId, []);
      byCheck.get(checkId)!.push({
        uid,
        sev: String(f.severity ?? "medium"),
      });
    }

    for (const [checkId, res] of byCheck) {
      // Connect consecutive resources in the group (chain) to show blast radius
      for (let i = 0; i < res.length - 1; i++) {
        const sev = res[i].sev || res[i + 1].sev || "medium";
        addEdge(res[i].uid, res[i + 1].uid, checkId, sev);
      }
    }

    // 3b. Severity hub edges: connect each failing resource to a severity hub
    const hubNodes = new Map<string, GraphNode>();
    for (const f of (sharedCheckRows.results ?? [])) {
      const uid = String(f.resource_uid ?? "");
      if (!uid || !nodeIds.has(uid)) continue;
      const sev = String(f.severity ?? "medium");
      const hubId = `hub-${sev}`;
      if (!hubNodes.has(hubId)) {
        hubNodes.set(hubId, {
          id: hubId,
          label: `${sev} risk hub`,
          provider: "hub",
          service: "risk",
          region: "global",
          risk: 0,
          findings: 0,
          severity: sev,
        });
      }
      addEdge(uid, hubId, `${sev} risk`, sev);
    }

    // Add hub nodes to the node list
    for (const hub of hubNodes.values()) {
      nodes.push(hub);
    }

    return json({ nodes, edges });
  } catch (err) {
    // Never crash — return empty graph so the page renders instead of 500
    return json({ nodes: [], edges: [] });
  }
}

// ── History ───────────────────────────────────────────────────────────────────
async function handleHistory(url: URL, env: Env) {
  const provider = url.searchParams.get("provider") ?? "";
  const days     = parseInt(url.searchParams.get("days") ?? "30");
  const where    = provider ? "WHERE provider = ?" : "";
  const binds    = provider ? [provider, days] : [days];

  const rows = await env.DB.prepare(
    `SELECT provider, score, checks_executed, total_checks, passed, failed,
            critical, high, medium, low,
            strftime('%Y-%m-%dT%H:00:00Z', scanned_at) as hour
     FROM scan_runs ${where}
     ORDER BY scanned_at DESC
     LIMIT ?`
  ).bind(...binds).all();

  return json({ history: rows.results });
}

// ── Router ────────────────────────────────────────────────────────────────────
export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    if (req.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS });
    }

    const url  = new URL(req.url);
    const path = url.pathname;

    if (req.method === "POST" && path === "/ingest")         return handleIngest(req, env);
    if (req.method === "GET"  && path === "/api/score")      return handleScore(env);
    if (req.method === "GET"  && path === "/api/findings")   return handleFindings(url, env);
    if (req.method === "GET"  && path === "/api/checks")     return handleChecks(url, env);
    if (req.method === "GET"  && path === "/api/services")   return handleServices(url, env);
    if (req.method === "GET"  && path === "/api/compliance") return handleCompliance(env);
    if (req.method === "GET"  && path === "/api/graph")      return handleGraph(env);
    if (req.method === "GET"  && path === "/api/history")    return handleHistory(url, env);

    return json({ error: "Not found" }, 404);
  },
};