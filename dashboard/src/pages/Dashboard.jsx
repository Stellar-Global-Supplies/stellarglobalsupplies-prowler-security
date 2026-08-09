import { useEffect, useState, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import * as d3 from 'd3'
import { api } from '../lib/api'

const SEV_COLOR = {
  critical: 'var(--critical)', high: 'var(--high)',
  medium: 'var(--medium)', low: 'var(--low)', informational: 'var(--muted)',
}
const SEV_BG = {
  critical: 'var(--critical-bg)', high: 'var(--high-bg)',
  medium: 'var(--medium-bg)', low: 'var(--low-bg)', informational: '#64748b15',
}

export default function Dashboard() {
  const [score,      setScore]      = useState(null)
  const [history,    setHistory]    = useState([])
  const [services,   setServices]   = useState([])
  const [compliance, setCompliance] = useState([])
  const [loading,    setLoading]    = useState(true)
  const navigate = useNavigate()

  useEffect(() => {
    Promise.all([
      api.score(),
      api.history({ days: 7 }),
      api.services({}),
      api.compliance(),
    ]).then(([s, h, sv, c]) => {
      setScore(s)
      setHistory(h.history ?? [])
      setServices(sv.services ?? [])
      setCompliance(c.breakdown ?? [])
      setLoading(false)
    }).catch(() => setLoading(false))
  }, [])

  if (loading) return <PageLoader />

  const critical = score?.critical ?? 0
  const high     = score?.high     ?? 0
  const medium   = score?.medium   ?? 0
  const low      = score?.low      ?? 0
  const pct      = score?.score    ?? 0
  const total    = score?.total    ?? 0
  const passed   = score?.passed   ?? 0
  const failed   = score?.failed   ?? 0

  return (
    <div style={{ display:'flex', flexDirection:'column', gap:20 }}>

      {/* Header */}
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start' }}>
        <div>
          <h1 style={{ fontSize:22, fontWeight:700, letterSpacing:'-0.03em', marginBottom:4 }}>Security Overview</h1>
          <p style={{ color:'var(--muted)', fontSize:13 }}>Scans run hourly · {total.toLocaleString()} checks executed</p>
        </div>
        <LastScanBadge byProvider={score?.by_provider ?? {}} />
      </div>

      {/* Top row: Gauge + 4 severity cards + pass/fail */}
      <div style={{ display:'grid', gridTemplateColumns:'200px 1fr', gap:16 }}>
        <ScoreGauge pct={pct} passed={passed} failed={failed} total={total} />
        <div style={{ display:'flex', flexDirection:'column', gap:10 }}>
          <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:10 }}>
            <SeverityCard label="Critical" count={critical} color="var(--critical)" bg="var(--critical-bg)" onClick={() => navigate('/findings?severity=critical&status=FAIL')} />
            <SeverityCard label="High"     count={high}     color="var(--high)"     bg="var(--high-bg)"     onClick={() => navigate('/findings?severity=high&status=FAIL')} />
            <SeverityCard label="Medium"   count={medium}   color="var(--medium)"   bg="var(--medium-bg)"   onClick={() => navigate('/findings?severity=medium&status=FAIL')} />
            <SeverityCard label="Low"      count={low}      color="var(--low)"      bg="var(--low-bg)"      onClick={() => navigate('/findings?severity=low&status=FAIL')} />
          </div>
          <PassFailBar passed={passed} failed={failed} total={total} />
        </div>
      </div>

      {/* Trend + Provider breakdown */}
      <div style={{ display:'grid', gridTemplateColumns:'1fr 280px', gap:16 }}>
        <TrendChart data={history} />
        <ProviderBreakdown byProvider={score?.by_provider ?? {}} />
      </div>

      {/* Services table + Compliance heatmap */}
      <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:16 }}>
        <ServicesTable services={services} onNavigate={navigate} />
        <ComplianceHeatmap data={compliance} />
      </div>

      {/* Quick actions */}
      <div style={{ display:'grid', gridTemplateColumns:'repeat(3,1fr)', gap:12 }}>
        <ActionCard
          icon="🔍"
          title="All Checks"
          desc={`${total.toLocaleString()} checks executed this scan`}
          color="var(--accent)"
          onClick={() => navigate('/findings')}
        />
        <ActionCard
          icon="⚠️"
          title="Open Findings"
          desc={`${failed.toLocaleString()} failures need attention`}
          color="var(--critical)"
          onClick={() => navigate('/findings?status=FAIL')}
        />
        <ActionCard
          icon="🕸️"
          title="Attack Graph"
          desc="Visualise misconfigurations across services"
          color="#a855f7"
          onClick={() => navigate('/attack-graph')}
        />
      </div>
    </div>
  )
}

// ── Score Gauge ───────────────────────────────────────────────────────────────
function ScoreGauge({ pct, passed, failed, total }) {
  const color = pct >= 80 ? 'var(--pass)' : pct >= 60 ? 'var(--medium)' : 'var(--critical)'
  const r = 54, cx = 100, cy = 100
  const circ = 2 * Math.PI * r
  return (
    <div style={{ background:'var(--surface)', border:'1px solid var(--border)', borderRadius:12, padding:20, display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center' }}>
      <svg width={200} height={130} viewBox="0 0 200 130">
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="var(--border2)" strokeWidth="10"
          strokeDasharray={`${circ * 0.75} ${circ * 0.25}`}
          strokeDashoffset={circ * 0.375} strokeLinecap="round"
          transform={`rotate(135 ${cx} ${cy})`} />
        <circle cx={cx} cy={cy} r={r} fill="none" stroke={color} strokeWidth="10"
          strokeDasharray={`${(pct / 100) * circ * 0.75} ${circ}`}
          strokeDashoffset={circ * 0.375} strokeLinecap="round"
          transform={`rotate(135 ${cx} ${cy})`}
          style={{ filter:`drop-shadow(0 0 8px ${color})`, transition:'stroke-dasharray 1s ease' }} />
        <text x={cx} y={cy + 4} textAnchor="middle" fill="white" fontSize="30" fontWeight="700" fontFamily="Inter">{pct}</text>
        <text x={cx} y={cy + 22} textAnchor="middle" fill="var(--muted)" fontSize="10" fontFamily="Inter">SECURITY SCORE</text>
      </svg>
      <div style={{ display:'flex', gap:16, marginTop:-4, fontSize:11 }}>
        <span style={{ color:'var(--pass)' }}>✓ {passed.toLocaleString()}</span>
        <span style={{ color:'var(--muted)' }}>|</span>
        <span style={{ color:'var(--critical)' }}>✗ {failed.toLocaleString()}</span>
      </div>
    </div>
  )
}

// ── Severity Card ─────────────────────────────────────────────────────────────
function SeverityCard({ label, count, color, bg, onClick }) {
  return (
    <button onClick={onClick} style={{ background:bg, border:`1px solid ${color}30`, borderRadius:10, padding:'16px 14px', textAlign:'left', cursor:'pointer', transition:'transform .15s, box-shadow .15s' }}
      onMouseEnter={e => { e.currentTarget.style.transform='translateY(-2px)'; e.currentTarget.style.boxShadow=`0 6px 20px ${color}20` }}
      onMouseLeave={e => { e.currentTarget.style.transform='none'; e.currentTarget.style.boxShadow='none' }}>
      <div style={{ fontSize:26, fontWeight:700, color, letterSpacing:'-0.03em', fontFamily:'JetBrains Mono, monospace' }}>{count.toLocaleString()}</div>
      <div style={{ fontSize:10, fontWeight:600, color, textTransform:'uppercase', letterSpacing:'0.08em', marginTop:4 }}>{label}</div>
      <div style={{ fontSize:10, color:'var(--muted)', marginTop:2 }}>open findings</div>
    </button>
  )
}

// ── Pass/Fail Bar ─────────────────────────────────────────────────────────────
function PassFailBar({ passed, failed, total }) {
  const passPct  = total > 0 ? (passed / total) * 100 : 0
  const failPct  = total > 0 ? (failed / total) * 100 : 0

  return (
    <div style={{ background:'var(--surface)', border:'1px solid var(--border)', borderRadius:10, padding:'14px 18px' }}>
      <div style={{ display:'flex', justifyContent:'space-between', marginBottom:8 }}>
        <span style={{ fontSize:12, fontWeight:500 }}>Check Results — {total.toLocaleString()} total</span>
        <div style={{ display:'flex', gap:14, fontSize:11 }}>
          <span style={{ color:'var(--pass)' }}>✓ {passed.toLocaleString()} passed ({passPct.toFixed(1)}%)</span>
          <span style={{ color:'var(--critical)' }}>✗ {failed.toLocaleString()} failed ({failPct.toFixed(1)}%)</span>
        </div>
      </div>
      <div style={{ height:8, borderRadius:4, background:'var(--border2)', overflow:'hidden', display:'flex' }}>
        <div style={{ height:'100%', width:`${passPct}%`, background:'var(--pass)', transition:'width 1s ease', boxShadow:'0 0 8px var(--pass)' }} />
        <div style={{ height:'100%', width:`${failPct}%`, background:'var(--critical)', transition:'width 1s ease' }} />
      </div>
    </div>
  )
}

// ── Trend Chart ───────────────────────────────────────────────────────────────
function TrendChart({ data }) {
  const ref = useRef(null)
  useEffect(() => {
    if (!ref.current || !data.length) return
    const el = ref.current
    d3.select(el).selectAll('*').remove()
    const W = el.clientWidth || 400, H = 160
    const margin = { top:10, right:10, bottom:24, left:38 }
    const w = W - margin.left - margin.right
    const h = H - margin.top - margin.bottom
    const svg = d3.select(el).append('svg').attr('width', W).attr('height', H)
    const g = svg.append('g').attr('transform', `translate(${margin.left},${margin.top})`)
    const parsed = data.map(d => ({ ...d, t: new Date(d.hour || d.scanned_at), s: +d.score })).sort((a, b) => a.t - b.t)
    if (parsed.length < 2) {
      g.append('text').attr('x', w/2).attr('y', h/2).attr('text-anchor','middle').attr('fill','var(--muted)').attr('font-size',12).text('More data after next scans')
      return
    }
    const x = d3.scaleTime().domain(d3.extent(parsed, d => d.t)).range([0, w])
    const y = d3.scaleLinear().domain([0, 100]).range([h, 0])
    g.append('g').call(d3.axisLeft(y).ticks(4).tickSize(-w).tickFormat(v => `${v}%`))
      .call(g2 => g2.select('.domain').remove())
      .call(g2 => g2.selectAll('.tick line').attr('stroke','var(--border)').attr('stroke-dasharray','3,3'))
      .call(g2 => g2.selectAll('.tick text').attr('fill','var(--muted)').attr('font-size',10))
    g.append('g').attr('transform', `translate(0,${h})`).call(d3.axisBottom(x).ticks(5).tickFormat(d3.timeFormat('%d %b %H:%M')))
      .call(g2 => g2.select('.domain').remove())
      .call(g2 => g2.selectAll('.tick line').remove())
      .call(g2 => g2.selectAll('.tick text').attr('fill','var(--muted)').attr('font-size',10))
    const grad = svg.append('defs').append('linearGradient').attr('id','tg').attr('x1',0).attr('x2',0).attr('y1',0).attr('y2',1)
    grad.append('stop').attr('offset','0%').attr('stop-color','var(--accent)').attr('stop-opacity',0.3)
    grad.append('stop').attr('offset','100%').attr('stop-color','var(--accent)').attr('stop-opacity',0.02)
    const area = d3.area().x(d => x(d.t)).y0(h).y1(d => y(d.s)).curve(d3.curveCatmullRom)
    const line = d3.line().x(d => x(d.t)).y(d => y(d.s)).curve(d3.curveCatmullRom)
    g.append('path').datum(parsed).attr('fill','url(#tg)').attr('d', area)
    g.append('path').datum(parsed).attr('fill','none').attr('stroke','var(--accent)').attr('stroke-width',2).attr('d', line).attr('filter','drop-shadow(0 0 6px var(--accent))')
    g.selectAll('circle').data(parsed).enter().append('circle').attr('cx', d => x(d.t)).attr('cy', d => y(d.s)).attr('r', 3).attr('fill','var(--accent)').attr('stroke','var(--bg)').attr('stroke-width',1.5)
  }, [data])
  return (
    <div style={{ background:'var(--surface)', border:'1px solid var(--border)', borderRadius:12, padding:'16px 20px' }}>
      <div style={{ fontSize:13, fontWeight:500, marginBottom:12 }}>Score Trend (7 days)</div>
      <div ref={ref} style={{ width:'100%' }} />
    </div>
  )
}

// ── Provider Breakdown ────────────────────────────────────────────────────────
function ProviderBreakdown({ byProvider }) {
  const entries = Object.entries(byProvider)
  return (
    <div style={{ background:'var(--surface)', border:'1px solid var(--border)', borderRadius:12, padding:'16px 20px' }}>
      <div style={{ fontSize:13, fontWeight:500, marginBottom:16 }}>By Provider</div>
      {entries.length === 0 && <div style={{ color:'var(--muted)', fontSize:12 }}>No data yet</div>}
      {entries.map(([provider, d]) => {
        const pct = d.score ?? 0
        const color = pct >= 80 ? 'var(--pass)' : pct >= 60 ? 'var(--medium)' : 'var(--critical)'
        return (
          <div key={provider} style={{ marginBottom:16 }}>
            <div style={{ display:'flex', justifyContent:'space-between', marginBottom:6 }}>
              <span style={{ fontSize:12, textTransform:'uppercase', letterSpacing:'0.06em', fontWeight:600 }}>{provider}</span>
              <span style={{ fontSize:12, color, fontFamily:'JetBrains Mono, monospace' }}>{pct}%</span>
            </div>
            <div style={{ height:6, borderRadius:3, background:'var(--border2)', overflow:'hidden' }}>
              <div style={{ height:'100%', width:`${pct}%`, background:color, borderRadius:3, boxShadow:`0 0 8px ${color}` }} />
            </div>
            <div style={{ display:'flex', gap:12, marginTop:6, fontSize:11, color:'var(--muted)', flexWrap:'wrap' }}>
              <span style={{ color:'var(--pass)' }}>✓ {(d.passed ?? 0).toLocaleString()} pass</span>
              <span style={{ color:'var(--critical)' }}>✗ {(d.failed ?? 0).toLocaleString()} fail</span>
              <span>📋 {(d.total_checks ?? 0).toLocaleString()} total</span>
            </div>
          </div>
        )
      })}
    </div>
  )
}

// ── Services Table ────────────────────────────────────────────────────────────
function ServicesTable({ services, onNavigate }) {
  const top = services.slice(0, 8)
  return (
    <div style={{ background:'var(--surface)', border:'1px solid var(--border)', borderRadius:12, overflow:'hidden' }}>
      <div style={{ padding:'14px 18px', borderBottom:'1px solid var(--border)', display:'flex', justifyContent:'space-between', alignItems:'center' }}>
        <span style={{ fontSize:13, fontWeight:500 }}>Services</span>
        <span style={{ fontSize:11, color:'var(--muted)' }}>{services.length} monitored</span>
      </div>
      <div style={{ overflowX:'auto' }}>
        <table style={{ width:'100%', borderCollapse:'collapse', fontSize:12 }}>
          <thead>
            <tr style={{ background:'var(--surface2)' }}>
              {['Service','Checks','Pass','Fail','Coverage'].map(h => (
                <th key={h} style={{ padding:'8px 14px', textAlign:'left', fontSize:10, fontWeight:600, color:'var(--muted)', textTransform:'uppercase', letterSpacing:'0.06em', whiteSpace:'nowrap' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {top.length === 0 && (
              <tr><td colSpan={5} style={{ padding:'24px', textAlign:'center', color:'var(--muted)' }}>No service data yet</td></tr>
            )}
            {top.map((svc, i) => {
              const total = (svc.passed ?? 0) + (svc.failed ?? 0)
              const pct   = total > 0 ? Math.round((svc.passed / total) * 100) : 0
              const color = pct >= 80 ? 'var(--pass)' : pct >= 60 ? 'var(--medium)' : 'var(--critical)'
              return (
                <tr key={i} style={{ borderTop:'1px solid var(--border)', cursor:'pointer' }}
                  onClick={() => onNavigate(`/findings?service=${svc.service}&provider=${svc.provider}`)}
                  onMouseEnter={e => e.currentTarget.style.background='var(--surface2)'}
                  onMouseLeave={e => e.currentTarget.style.background='transparent'}>
                  <td style={{ padding:'9px 14px', fontFamily:'JetBrains Mono, monospace', color:'var(--accent)' }}>{svc.service || '—'}</td>
                  <td style={{ padding:'9px 14px', color:'var(--muted)' }}>{svc.check_count ?? 0}</td>
                  <td style={{ padding:'9px 14px', color:'var(--pass)' }}>{(svc.passed ?? 0).toLocaleString()}</td>
                  <td style={{ padding:'9px 14px', color: svc.failed > 0 ? 'var(--critical)' : 'var(--muted)' }}>
                    {svc.failed > 0 ? `✗ ${svc.failed.toLocaleString()}` : '—'}
                  </td>
                  <td style={{ padding:'9px 14px', minWidth:100 }}>
                    <div style={{ display:'flex', alignItems:'center', gap:6 }}>
                      <div style={{ flex:1, height:4, borderRadius:2, background:'var(--border2)', overflow:'hidden' }}>
                        <div style={{ height:'100%', width:`${pct}%`, background:color }} />
                      </div>
                      <span style={{ fontSize:10, color, minWidth:28 }}>{pct}%</span>
                    </div>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ── Compliance Heatmap (severity × provider) ──────────────────────────────────
function ComplianceHeatmap({ data }) {
  const sevOrder = ['critical','high','medium','low','informational']
  const providers = [...new Set(data.map(d => d.provider))]

  const cell = (provider, severity) => {
    const row = data.find(d => d.provider === provider && d.severity === severity)
    if (!row) return null
    const total = (row.passed ?? 0) + (row.failed ?? 0)
    const pct   = total > 0 ? Math.round((row.passed / total) * 100) : 0
    return { ...row, pct, total }
  }

  return (
    <div style={{ background:'var(--surface)', border:'1px solid var(--border)', borderRadius:12, overflow:'hidden' }}>
      <div style={{ padding:'14px 18px', borderBottom:'1px solid var(--border)' }}>
        <span style={{ fontSize:13, fontWeight:500 }}>Coverage by Severity</span>
      </div>
      <div style={{ padding:16 }}>
        {data.length === 0 && <div style={{ color:'var(--muted)', fontSize:12, textAlign:'center', padding:24 }}>No data yet</div>}
        {data.length > 0 && (
          <table style={{ width:'100%', borderCollapse:'separate', borderSpacing:4 }}>
            <thead>
              <tr>
                <th style={{ fontSize:10, color:'var(--muted)', textAlign:'left', padding:'0 4px 8px', textTransform:'uppercase', letterSpacing:'0.06em' }}>Severity</th>
                {providers.map(p => (
                  <th key={p} style={{ fontSize:10, color:'var(--muted)', padding:'0 4px 8px', textTransform:'uppercase', letterSpacing:'0.06em' }}>{p}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {sevOrder.map(sev => (
                <tr key={sev}>
                  <td style={{ padding:'4px 4px', fontSize:11, color: SEV_COLOR[sev] ?? 'var(--muted)', fontWeight:500, textTransform:'capitalize', whiteSpace:'nowrap' }}>
                    <span style={{ display:'inline-block', width:6, height:6, borderRadius:'50%', background: SEV_COLOR[sev] ?? 'var(--muted)', marginRight:6, verticalAlign:'middle' }}/>
                    {sev}
                  </td>
                  {providers.map(p => {
                    const c = cell(p, sev)
                    if (!c) return <td key={p} style={{ padding:4 }}><div style={{ height:36, borderRadius:6, background:'var(--border)', opacity:0.3 }}/></td>
                    const bg = c.pct >= 80 ? '#10b98120' : c.pct >= 60 ? '#eab30820' : '#ef444420'
                    const fc = c.pct >= 80 ? 'var(--pass)' : c.pct >= 60 ? 'var(--medium)' : 'var(--critical)'
                    return (
                      <td key={p} style={{ padding:4 }}>
                        <div title={`${c.passed}/${c.total} passed`} style={{ height:36, borderRadius:6, background:bg, border:`1px solid ${fc}30`, display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center', cursor:'default' }}>
                          <span style={{ fontSize:11, fontWeight:700, color:fc, fontFamily:'JetBrains Mono, monospace' }}>{c.pct}%</span>
                          <span style={{ fontSize:9, color:'var(--muted)' }}>{c.checks} checks</span>
                        </div>
                      </td>
                    )
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

// ── Last Scan Badge ───────────────────────────────────────────────────────────
function LastScanBadge({ byProvider }) {
  const times = Object.values(byProvider).map(d => d.scanned_at).filter(Boolean)
  if (!times.length) return null
  const latest = new Date(Math.max(...times.map(t => new Date(t))))
  const ago = Math.round((Date.now() - latest) / 60000)
  const label = ago < 60 ? `${ago}m ago` : `${Math.round(ago/60)}h ago`
  return (
    <div style={{ display:'flex', alignItems:'center', gap:6, padding:'6px 12px', background:'var(--surface)', border:'1px solid var(--border)', borderRadius:8, fontSize:11 }}>
      <span style={{ width:6, height:6, borderRadius:'50%', background:'var(--pass)', display:'inline-block', boxShadow:'0 0 6px var(--pass)' }}/>
      <span style={{ color:'var(--muted)' }}>Last scan</span>
      <span style={{ color:'var(--text)', fontWeight:500 }}>{label}</span>
    </div>
  )
}

// ── Action Card ───────────────────────────────────────────────────────────────
function ActionCard({ icon, title, desc, color, onClick }) {
  return (
    <button onClick={onClick} style={{ background:`linear-gradient(135deg, var(--surface) 0%, ${color}08 100%)`, border:`1px solid ${color}25`, borderRadius:12, padding:'16px 18px', textAlign:'left', cursor:'pointer', transition:'transform .15s, box-shadow .15s' }}
      onMouseEnter={e => { e.currentTarget.style.transform='translateY(-2px)'; e.currentTarget.style.boxShadow=`0 8px 24px ${color}15` }}
      onMouseLeave={e => { e.currentTarget.style.transform='none'; e.currentTarget.style.boxShadow='none' }}>
      <div style={{ fontSize:20, marginBottom:6 }}>{icon}</div>
      <div style={{ fontSize:13, fontWeight:600, marginBottom:4, color }}>{title} →</div>
      <div style={{ fontSize:11, color:'var(--muted)' }}>{desc}</div>
    </button>
  )
}

function PageLoader() {
  return (
    <div style={{ display:'flex', alignItems:'center', justifyContent:'center', height:'60vh', color:'var(--muted)', fontSize:13 }}>
      Loading security data…
    </div>
  )
}