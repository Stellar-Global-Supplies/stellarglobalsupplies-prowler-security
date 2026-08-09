/**
 * Prowler Security Dashboard — Cloudflare Worker API
 * Endpoints:
 *   POST /ingest          — receive findings from GitHub Actions (auth required)
 *   GET  /api/score       — overall posture score + severity counts
 *   GET  /api/findings    — paginated findings list with filters
 *   GET  /api/graph       — nodes + edges for D3 attack graph
 *   GET  /api/history     — scan history for trend chart
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

  const body = await req.json<{
    scan_run: Record<string, unknown>;
    findings: Record<string, unknown>[];
    resources: Record<string, unknown>[];
    edges: Record<string, unknown>[];
  }>();

  const { scan_run, findings, resources, edges } = body;

  // Insert scan run (only on first batch when full data is present)
  if (scan_run.provider && scan_run.scanned_at) {
    await env.DB.prepare(
      `INSERT OR REPLACE INTO scan_runs
       (id, provider, scanned_at, total_checks, passed, failed, critical, high, medium, low, score)
       VALUES (?,?,?,?,?,?,?,?,?,?,?)`
    )
      .bind(
        scan_run.id, scan_run.provider, scan_run.scanned_at,
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
    `SELECT provider, score, total_checks, passed, failed,
            critical, high, medium, low, scanned_at
     FROM scan_runs
     ORDER BY scanned_at DESC
     LIMIT 10`
  ).all();

  // Aggregate across providers for the latest scan per provider
  const byProvider: Record<string, unknown> = {};
  const seen = new Set<string>();
  for (const row of latest.results) {
    const p = row.provider as string;
    if (!seen.has(p)) {
      seen.add(p);
      byProvider[p] = row;
    }
  }

  const totals = Object.values(byProvider).reduce(
    (acc: Record<string, number>, r: unknown) => {
      const row = r as Record<string, number>;
      acc.total += row.total_checks ?? 0;
      acc.passed += row.passed ?? 0;
      acc.failed += row.failed ?? 0;
      acc.critical += row.critical ?? 0;
      acc.high += row.high ?? 0;
      acc.medium += row.medium ?? 0;
      acc.low += row.low ?? 0;
      return acc;
    },
    { total: 0, passed: 0, failed: 0, critical: 0, high: 0, medium: 0, low: 0 }
  );

  const score =
    totals.total > 0 ? Math.round((totals.passed / totals.total) * 100) : 0;

  return json({ score, ...totals, by_provider: byProvider });
}

// ── Findings ─────────────────────────────────────────────────────────────────
async function handleFindings(url: URL, env: Env) {
  const severity = url.searchParams.get("severity") ?? "";
  const status = url.searchParams.get("status") ?? "";
  const provider = url.searchParams.get("provider") ?? "";
  const search = url.searchParams.get("q") ?? "";
  const page = parseInt(url.searchParams.get("page") ?? "1");
  const limit = Math.min(parseInt(url.searchParams.get("limit") ?? "50"), 200);
  const offset = (page - 1) * limit;

  const conditions: string[] = [];
  const binds: (string | number)[] = [];

  if (severity) { conditions.push("severity = ?"); binds.push(severity); }
  if (status)   { conditions.push("status = ?");   binds.push(status); }
  if (provider) { conditions.push("provider = ?"); binds.push(provider); }
  if (search) {
    conditions.push("(check_title LIKE ? OR resource_name LIKE ? OR description LIKE ?)");
    const q = `%${search}%`;
    binds.push(q, q, q);
  }

  const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";

  const [rows, countRow] = await Promise.all([
    env.DB.prepare(
      `SELECT id, provider, service, check_id, check_title, status, severity,
              resource_name, resource_type, region, description, remediation, scanned_at
       FROM findings ${where}
       ORDER BY
         CASE severity
           WHEN 'critical' THEN 1 WHEN 'high' THEN 2
           WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5
         END,
         scanned_at DESC
       LIMIT ? OFFSET ?`
    )
      .bind(...binds, limit, offset)
      .all(),
    env.DB.prepare(`SELECT COUNT(*) as total FROM findings ${where}`)
      .bind(...binds)
      .first<{ total: number }>(),
  ]);

  return json({
    findings: rows.results,
    total: countRow?.total ?? 0,
    page,
    limit,
  });
}

// ── Graph ─────────────────────────────────────────────────────────────────────
async function handleGraph(env: Env) {
  const [resourceRows, edgeRows] = await Promise.all([
    env.DB.prepare(
      `SELECT r.id, r.provider, r.service, r.resource_type,
              r.resource_name, r.region, r.risk_score,
              COUNT(f.id) as finding_count,
              MAX(CASE f.severity
                WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0
              END) as max_severity
       FROM resources r
       LEFT JOIN findings f ON f.resource_uid = r.resource_uid AND f.status = 'FAIL'
       GROUP BY r.id
       LIMIT 200`
    ).all(),
    env.DB.prepare(
      `SELECT source_id, target_id, source_label, target_label, relationship, severity
       FROM graph_edges LIMIT 500`
    ).all(),
  ]);

  const nodes = resourceRows.results.map((r) => ({
    id: r.id,
    label: r.resource_name || r.service,
    provider: r.provider,
    service: r.service,
    region: r.region,
    risk: r.risk_score,
    findings: r.finding_count,
    severity: ["low", "low", "medium", "high", "critical"][
      (r.max_severity as number) ?? 0
    ],
  }));

  return json({ nodes, edges: edgeRows.results });
}

// ── History ───────────────────────────────────────────────────────────────────
async function handleHistory(url: URL, env: Env) {
  const provider = url.searchParams.get("provider") ?? "";
  const days = parseInt(url.searchParams.get("days") ?? "30");
  const where = provider ? "WHERE provider = ?" : "";
  const binds = provider ? [provider, days] : [days];

  const rows = await env.DB.prepare(
    `SELECT provider, score, total_checks, passed, failed,
            critical, high, medium, low,
            strftime('%Y-%m-%dT%H:00:00Z', scanned_at) as hour
     FROM scan_runs ${where}
     ORDER BY scanned_at DESC
     LIMIT ?`
  )
    .bind(...binds)
    .all();

  return json({ history: rows.results });
}

// ── Router ────────────────────────────────────────────────────────────────────
export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    if (req.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS });
    }

    const url = new URL(req.url);
    const path = url.pathname;

    if (req.method === "POST" && path === "/ingest") return handleIngest(req, env);
    if (req.method === "GET"  && path === "/api/score")    return handleScore(env);
    if (req.method === "GET"  && path === "/api/findings") return handleFindings(url, env);
    if (req.method === "GET"  && path === "/api/graph")    return handleGraph(env);
    if (req.method === "GET"  && path === "/api/history")  return handleHistory(url, env);

    return json({ error: "Not found" }, 404);
  },
};
