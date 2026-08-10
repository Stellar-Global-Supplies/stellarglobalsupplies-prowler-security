// VITE_API_URL is set at build time in Cloudflare Pages. Fall back to the
// real worker URL so the dashboard works even if the env var is missing or
// still set to the README placeholder (prowler-api.yourname.workers.dev).
const BASE = import.meta.env.VITE_API_URL || 'https://prowler-api.workwithprasadbhavsar.workers.dev'

async function get(path) {
  const res = await fetch(`${BASE}${path}`)
  if (!res.ok) throw new Error(`API error ${res.status}`)
  return res.json()
}

export const api = {
  score:      ()       => get('/api/score'),
  findings:   (params) => get(`/api/findings?${new URLSearchParams(params)}`),
  checks:     (params) => get(`/api/checks?${new URLSearchParams(params)}`),
  services:   (params) => get(`/api/services?${new URLSearchParams(params)}`),
  compliance: ()       => get('/api/compliance'),
  graph:      ()       => get('/api/graph'),
  history:    (params) => get(`/api/history?${new URLSearchParams(params)}`),
}