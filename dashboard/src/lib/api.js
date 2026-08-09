const BASE = import.meta.env.VITE_API_URL  // e.g. https://prowler-api.yourname.workers.dev

async function get(path) {
  const res = await fetch(`${BASE}${path}`)
  if (!res.ok) throw new Error(`API error ${res.status}`)
  return res.json()
}

export const api = {
  score:    ()       => get('/api/score'),
  findings: (params) => get(`/api/findings?${new URLSearchParams(params)}`),
  graph:    ()       => get('/api/graph'),
  history:  (params) => get(`/api/history?${new URLSearchParams(params)}`),
}
