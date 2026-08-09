import { useEffect, useState, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import * as d3 from 'd3'
import { api } from '../lib/api'

export default function Dashboard() {
  const [score, setScore]     = useState(null)
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()

  useEffect(() => {
    Promise.all([api.score(), api.history({ days: 7 })]).then(([s, h]) => {
      setScore(s)
      setHistory(h.history ?? [])
      setLoading(false)
    }).catch(() => setLoading(false))
  }, [])

  if (loading) return <PageLoader />

  const critical = score?.critical ?? 0
  const high     = score?.high ?? 0
  const medium   = score?.medium ?? 0
  const low      = score?.low ?? 0
  const pct      = score?.score ?? 0

  return (
    <div>
      {/* Header */}
      <div style={{ marginBottom:28 }}>
        <h1 style={{ fontSize:22, fontWeight:700, letterSpacing:'-0.03em', marginBottom:4 }}>Security Overview</h1>
        <p style={{ color:'var(--muted)', fontSize:13 }}>Scans run hourly across AWS and Cloudflare</p>
      </div>

      {/* Score + Cards row */}
      <div style={{ display:'grid', gridTemplateColumns:'200px 1fr', gap:20, marginBottom:24 }}>
        <ScoreGauge pct={pct} />
        <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:12 }}>
          <SeverityCard label="Critical" count={critical} color="var(--critical)" bg="var(--critical-bg)" onClick={() => navigate('/findings?severity=critical')} />
          <SeverityCard label="High"     count={high}     color="var(--high)"     bg="var(--high-bg)"     onClick={() => navigate('/findings?severity=high')} />
          <SeverityCard label="Medium"   count={medium}   color="var(--medium)"   bg="var(--medium-bg)"   onClick={() => navigate('/findings?severity=medium')} />
          <SeverityCard label="Low"      count={low}      color="var(--low)"      bg="var(--low-bg)"      onClick={() => navigate('/findings?severity=low')} />
        </div>
      </div>

      {/* Pass/Fail bar */}
      <PassFailBar passed={score?.passed ?? 0} failed={score?.failed ?? 0} />

      {/* Trend + Provider breakdown */}
      <div style={{ display:'grid', gridTemplateColumns:'1fr 280px', gap:20, marginTop:20 }}>
        <TrendChart data={history} />
        <ProviderBreakdown byProvider={score?.by_provider ?? {}} />
      </div>

      {/* Quick actions */}
      <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:12, marginTop:20 }}>
        <ActionCard
          title="View all findings"
          desc={`${(score?.failed ?? 0)} active issues across your infrastructure`}
          color="var(--critical)"
          onClick={() => navigate('/findings')}
        />
        <ActionCard
          title="Explore attack paths"
          desc="See how misconfigurations connect across services"
          color="var(--accent)"
          onClick={() => navigate('/attack-graph')}
        />
      </div>
    </div>
  )
}

// ── Score Gauge ───────────────────────────────────────────────────────────────
function ScoreGauge({ pct }) {
  const color = pct >= 80 ? 'var(--pass)' : pct >= 60 ? 'var(--medium)' : 'var(--critical)'
  const r = 58, cx = 100, cy = 100
  const circ = 2 * Math.PI * r
  const progress = circ - (pct / 100) * circ

  return (
    <div style={{ background:'var(--surface)', border:'1px solid var(--border)', borderRadius:12, padding:20, display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center' }}>
      <svg width={200} height={140} viewBox="0 0 200 140">
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="var(--border2)" strokeWidth="10" strokeDasharray={`${circ * 0.75} ${circ * 0.25}`} strokeDashoffset={circ * 0.375} strokeLinecap="round" transform={`rotate(135 ${cx} ${cy})`} />
        <circle cx={cx} cy={cy} r={r} fill="none" stroke={color} strokeWidth="10"
          strokeDasharray={`${(pct / 100) * circ * 0.75} ${circ}`}
          strokeDashoffset={circ * 0.375}
          strokeLinecap="round"
          transform={`rotate(135 ${cx} ${cy})`}
          style={{ filter:`drop-shadow(0 0 8px ${color})`, transition:'stroke-dasharray 1s ease' }}
        />
        <text x={cx} y={cy + 6} textAnchor="middle" fill="white" fontSize="28" fontWeight="700" fontFamily="Inter">{pct}</text>
        <text x={cx} y={cy + 24} textAnchor="middle" fill="var(--muted)" fontSize="11" fontFamily="Inter">SCORE</text>
      </svg>
      <div style={{ fontSize:11, color:'var(--muted)', marginTop:-8 }}>Security Posture</div>
    </div>
  )
}

// ── Severity Card ─────────────────────────────────────────────────────────────
function SeverityCard({ label, count, color, bg, onClick }) {
  return (
    <button onClick={onClick} style={{
      background: bg, border:`1px solid ${color}30`, borderRadius:12,
      padding:'20px 16px', textAlign:'left', cursor:'pointer',
      transition:'transform .15s, box-shadow .15s',
    }}
      onMouseEnter={e => { e.currentTarget.style.transform='translateY(-2px)'; e.currentTarget.style.boxShadow=`0 8px 24px ${color}20` }}
      onMouseLeave={e => { e.currentTarget.style.transform='none'; e.currentTarget.style.boxShadow='none' }}
    >
      <div style={{ fontSize:28, fontWeight:700, color, letterSpacing:'-0.03em', fontFamily:'JetBrains Mono, monospace' }}>{count}</div>
      <div style={{ fontSize:11, fontWeight:600, color, textTransform:'uppercase', letterSpacing:'0.08em', marginTop:4 }}>{label}</div>
      <div style={{ fontSize:11, color:'var(--muted)', marginTop:2 }}>active issues</div>
    </button>
  )
}

// ── Pass/Fail Bar ─────────────────────────────────────────────────────────────
function PassFailBar({ passed, failed }) {
  const total = passed + failed || 1
  const passPct = (passed / total) * 100

  return (
    <div style={{ background:'var(--surface)', border:'1px solid var(--border)', borderRadius:12, padding:'16px 20px' }}>
      <div style={{ display:'flex', justifyContent:'space-between', marginBottom:10 }}>
        <span style={{ fontSize:13, fontWeight:500 }}>Check Results</span>
        <div style={{ display:'flex', gap:16, fontSize:12 }}>
          <span style={{ color:'var(--pass)' }}>✓ {passed} passed</span>
          <span style={{ color:'var(--critical)' }}>✗ {failed} failed</span>
        </div>
      </div>
      <div style={{ height:8, borderRadius:4, background:'var(--critical-bg)', overflow:'hidden' }}>
        <div style={{ height:'100%', width:`${passPct}%`, background:'var(--pass)', borderRadius:4, transition:'width 1s ease', boxShadow:'0 0 8px var(--pass)' }} />
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
    const margin = { top:10, right:10, bottom:24, left:36 }
    const w = W - margin.left - margin.right
    const h = H - margin.top - margin.bottom

    const svg = d3.select(el).append('svg').attr('width', W).attr('height', H)
    const g = svg.append('g').attr('transform', `translate(${margin.left},${margin.top})`)

    const parsed = data.map(d => ({ ...d, t: new Date(d.hour || d.scanned_at), s: +d.score }))
      .sort((a, b) => a.t - b.t)

    if (parsed.length < 2) {
      g.append('text').attr('x', w/2).attr('y', h/2).attr('text-anchor','middle').attr('fill','var(--muted)').attr('font-size',12).text('More data after next scans')
      return
    }

    const x = d3.scaleTime().domain(d3.extent(parsed, d => d.t)).range([0, w])
    const y = d3.scaleLinear().domain([0, 100]).range([h, 0])

    // Grid
    g.append('g').call(d3.axisLeft(y).ticks(4).tickSize(-w).tickFormat(v => `${v}%`))
      .call(g2 => g2.select('.domain').remove())
      .call(g2 => g2.selectAll('.tick line').attr('stroke','var(--border)').attr('stroke-dasharray','3,3'))
      .call(g2 => g2.selectAll('.tick text').attr('fill','var(--muted)').attr('font-size',10))

    g.append('g').attr('transform', `translate(0,${h})`).call(d3.axisBottom(x).ticks(5).tickFormat(d3.timeFormat('%d %b %H:%M')))
      .call(g2 => g2.select('.domain').remove())
      .call(g2 => g2.selectAll('.tick line').remove())
      .call(g2 => g2.selectAll('.tick text').attr('fill','var(--muted)').attr('font-size',10))

    // Area fill
    const area = d3.area().x(d => x(d.t)).y0(h).y1(d => y(d.s)).curve(d3.curveCatmullRom)
    const grad = svg.append('defs').append('linearGradient').attr('id','trendGrad').attr('x1',0).attr('x2',0).attr('y1',0).attr('y2',1)
    grad.append('stop').attr('offset','0%').attr('stop-color','var(--accent)').attr('stop-opacity',0.3)
    grad.append('stop').attr('offset','100%').attr('stop-color','var(--accent)').attr('stop-opacity',0.02)

    g.append('path').datum(parsed).attr('fill','url(#trendGrad)').attr('d', area)

    // Line
    const line = d3.line().x(d => x(d.t)).y(d => y(d.s)).curve(d3.curveCatmullRom)
    g.append('path').datum(parsed).attr('fill','none').attr('stroke','var(--accent)').attr('stroke-width',2).attr('d', line)
      .attr('filter','drop-shadow(0 0 6px var(--accent))')

    // Dots
    g.selectAll('circle').data(parsed).enter().append('circle')
      .attr('cx', d => x(d.t)).attr('cy', d => y(d.s)).attr('r', 3)
      .attr('fill','var(--accent)').attr('stroke','var(--bg)').attr('stroke-width',1.5)
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
      {entries.map(([provider, data]) => {
        const d = data
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
            <div style={{ display:'flex', gap:10, marginTop:6, fontSize:11, color:'var(--muted)' }}>
              <span style={{ color:'var(--critical)' }}>●</span> {d.critical ?? 0} critical
              <span style={{ color:'var(--high)' }}>●</span> {d.high ?? 0} high
            </div>
          </div>
        )
      })}
    </div>
  )
}

// ── Action Card ───────────────────────────────────────────────────────────────
function ActionCard({ title, desc, color, onClick }) {
  return (
    <button onClick={onClick} style={{
      background:`linear-gradient(135deg, var(--surface) 0%, ${color}08 100%)`,
      border:`1px solid ${color}25`, borderRadius:12, padding:'16px 20px',
      textAlign:'left', cursor:'pointer', transition:'transform .15s, box-shadow .15s',
    }}
      onMouseEnter={e => { e.currentTarget.style.transform='translateY(-2px)'; e.currentTarget.style.boxShadow=`0 8px 24px ${color}15` }}
      onMouseLeave={e => { e.currentTarget.style.transform='none'; e.currentTarget.style.boxShadow='none' }}
    >
      <div style={{ fontSize:14, fontWeight:600, marginBottom:4, color }}>{title} →</div>
      <div style={{ fontSize:12, color:'var(--muted)' }}>{desc}</div>
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
