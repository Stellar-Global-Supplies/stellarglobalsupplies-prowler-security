import { useEffect, useState, useCallback } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api } from '../lib/api'

const SEVERITY_ORDER = ['critical','high','medium','low','informational']
const SEVERITY_COLOR = {
  critical: 'var(--critical)', high: 'var(--high)',
  medium: 'var(--medium)', low: 'var(--low)', informational: 'var(--muted)'
}
const SEVERITY_BG = {
  critical: 'var(--critical-bg)', high: 'var(--high-bg)',
  medium: 'var(--medium-bg)', low: 'var(--low-bg)', informational: '#64748b15'
}

export default function Findings() {
  const [params, setParams] = useSearchParams()
  const [findings, setFindings]   = useState([])
  const [total, setTotal]         = useState(0)
  const [loading, setLoading]     = useState(true)
  const [expanded, setExpanded]   = useState(null)
  const [page, setPage]           = useState(1)

  const severity = params.get('severity') ?? ''
  const status   = params.get('status')   ?? 'FAIL'
  const provider = params.get('provider') ?? ''
  const q        = params.get('q')        ?? ''

  const load = useCallback(() => {
    setLoading(true)
    api.findings({ severity, status, provider, q, page, limit: 50 })
      .then(data => { setFindings(data.findings ?? []); setTotal(data.total ?? 0) })
      .finally(() => setLoading(false))
  }, [severity, status, provider, q, page])

  useEffect(() => { load() }, [load])

  function setFilter(key, val) {
    const next = new URLSearchParams(params)
    val ? next.set(key, val) : next.delete(key)
    setParams(next); setPage(1)
  }

  const pages = Math.ceil(total / 50)

  return (
    <div>
      {/* Header */}
      <div style={{ marginBottom:24 }}>
        <h1 style={{ fontSize:22, fontWeight:700, letterSpacing:'-0.03em', marginBottom:4 }}>Findings</h1>
        <p style={{ color:'var(--muted)', fontSize:13 }}>{total.toLocaleString()} total results</p>
      </div>

      {/* Filters */}
      <div style={{ display:'flex', gap:10, marginBottom:18, flexWrap:'wrap' }}>
        {/* Search */}
        <div style={{ flex:1, minWidth:200, position:'relative' }}>
          <SearchIcon style={{ position:'absolute', left:10, top:'50%', transform:'translateY(-50%)', color:'var(--muted)' }} />
          <input
            placeholder="Search findings, resources…"
            defaultValue={q}
            onChange={e => setFilter('q', e.target.value)}
            style={{
              width:'100%', padding:'8px 12px 8px 34px',
              background:'var(--surface)', border:'1px solid var(--border)',
              borderRadius:8, color:'var(--text)', fontSize:13, outline:'none',
            }}
          />
        </div>

        {/* Status toggle */}
        <StatusToggle value={status} onChange={v => setFilter('status', v)} />

        {/* Severity */}
        <FilterSelect value={severity} onChange={v => setFilter('severity', v)} placeholder="All severities">
          {SEVERITY_ORDER.map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase()+s.slice(1)}</option>)}
        </FilterSelect>

        {/* Provider */}
        <FilterSelect value={provider} onChange={v => setFilter('provider', v)} placeholder="All providers">
          <option value="aws">AWS</option>
          <option value="cloudflare">Cloudflare</option>
        </FilterSelect>

        {/* Clear */}
        {(severity || provider || q) && (
          <button onClick={() => setParams(new URLSearchParams({ status }))} style={{
            padding:'8px 14px', background:'transparent', border:'1px solid var(--border)',
            borderRadius:8, color:'var(--muted)', fontSize:13, cursor:'pointer'
          }}>Clear</button>
        )}
      </div>

      {/* Table */}
      <div style={{ background:'var(--surface)', border:'1px solid var(--border)', borderRadius:12, overflow:'hidden' }}>
        {/* Table header */}
        <div style={{
          display:'grid', gridTemplateColumns:'100px 80px 120px 1fr 140px 90px',
          gap:12, padding:'10px 16px',
          borderBottom:'1px solid var(--border)',
          fontSize:11, fontWeight:600, color:'var(--muted)',
          textTransform:'uppercase', letterSpacing:'0.06em',
          background:'var(--surface2)',
        }}>
          <span>Severity</span>
          <span>Provider</span>
          <span>Service</span>
          <span>Check</span>
          <span>Resource</span>
          <span>Status</span>
        </div>

        {loading && (
          <div style={{ padding:40, textAlign:'center', color:'var(--muted)', fontSize:13 }}>Loading…</div>
        )}

        {!loading && findings.length === 0 && (
          <div style={{ padding:40, textAlign:'center', color:'var(--muted)', fontSize:13 }}>
            No findings match the current filters
          </div>
        )}

        {!loading && findings.map((f, i) => (
          <FindingRow
            key={f.id}
            finding={f}
            expanded={expanded === f.id}
            onToggle={() => setExpanded(expanded === f.id ? null : f.id)}
            isEven={i % 2 === 0}
          />
        ))}
      </div>

      {/* Pagination */}
      {pages > 1 && (
        <div style={{ display:'flex', justifyContent:'center', gap:8, marginTop:16 }}>
          <PageBtn disabled={page<=1}  onClick={() => setPage(p=>p-1)}>← Prev</PageBtn>
          <span style={{ padding:'6px 12px', fontSize:12, color:'var(--muted)' }}>Page {page} of {pages}</span>
          <PageBtn disabled={page>=pages} onClick={() => setPage(p=>p+1)}>Next →</PageBtn>
        </div>
      )}
    </div>
  )
}

function FindingRow({ finding: f, expanded, onToggle, isEven }) {
  const sev = (f.severity ?? 'low').toLowerCase()
  const color = SEVERITY_COLOR[sev] ?? 'var(--muted)'
  const bg    = SEVERITY_BG[sev]   ?? '#64748b15'

  return (
    <>
      <div
        onClick={onToggle}
        style={{
          display:'grid', gridTemplateColumns:'100px 80px 120px 1fr 140px 90px',
          gap:12, padding:'11px 16px',
          borderBottom:'1px solid var(--border)',
          cursor:'pointer', fontSize:13,
          background: isEven ? 'transparent' : 'var(--surface2)',
          transition:'background .1s',
        }}
        onMouseEnter={e => e.currentTarget.style.background='var(--accent-glow)'}
        onMouseLeave={e => e.currentTarget.style.background= isEven ? 'transparent' : 'var(--surface2)'}
      >
        {/* Severity */}
        <span style={{
          display:'inline-flex', alignItems:'center', gap:5,
          padding:'2px 8px', borderRadius:5,
          background: bg, color, fontSize:11, fontWeight:600,
          textTransform:'uppercase', letterSpacing:'0.05em', width:'fit-content',
        }}>
          <span style={{ width:5, height:5, borderRadius:'50%', background:color, boxShadow:`0 0 5px ${color}` }}/>
          {sev}
        </span>

        {/* Provider */}
        <span style={{ color:'var(--muted)', alignSelf:'center', textTransform:'uppercase', fontSize:11 }}>
          {f.provider}
        </span>

        {/* Service */}
        <span style={{ color:'var(--text)', alignSelf:'center', fontFamily:'JetBrains Mono, monospace', fontSize:12 }}>
          {f.service || '—'}
        </span>

        {/* Check title */}
        <span style={{ color:'var(--text)', alignSelf:'center', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
          {f.check_title || f.check_id}
        </span>

        {/* Resource */}
        <span style={{ color:'var(--muted)', alignSelf:'center', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap', fontSize:12, fontFamily:'JetBrains Mono, monospace' }}>
          {f.resource_name || '—'}
        </span>

        {/* Status */}
        <span style={{
          alignSelf:'center',
          color: f.status === 'PASS' ? 'var(--pass)' : 'var(--critical)',
          fontWeight:600, fontSize:11,
        }}>
          {f.status === 'PASS' ? '✓ PASS' : '✗ FAIL'}
        </span>
      </div>

      {/* Expanded detail */}
      {expanded && (
        <div style={{
          padding:'16px 20px 20px',
          borderBottom:'1px solid var(--border)',
          background:`linear-gradient(to right, ${bg}, transparent)`,
          borderLeft:`3px solid ${color}`,
        }}>
          <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:16 }}>
            <div>
              <Label>Description</Label>
              <p style={{ fontSize:13, color:'var(--text)', lineHeight:1.6 }}>{f.description || 'No description available.'}</p>
            </div>
            <div>
              <Label>Remediation</Label>
              <p style={{ fontSize:13, color:'var(--text)', lineHeight:1.6 }}>{f.remediation || 'No remediation guidance available.'}</p>
            </div>
          </div>
          <div style={{ display:'flex', gap:24, marginTop:14, flexWrap:'wrap' }}>
            <Meta label="Check ID"  value={f.check_id} mono />
            <Meta label="Region"    value={f.region || 'global'} />
            <Meta label="Scanned"   value={f.scanned_at ? new Date(f.scanned_at).toLocaleString() : '—'} />
            <Meta label="Resource"  value={f.resource_uid || f.resource_name || '—'} mono />
          </div>
        </div>
      )}
    </>
  )
}

function Label({ children }) {
  return <div style={{ fontSize:10, fontWeight:600, color:'var(--muted)', textTransform:'uppercase', letterSpacing:'0.07em', marginBottom:6 }}>{children}</div>
}

function Meta({ label, value, mono }) {
  return (
    <div>
      <div style={{ fontSize:10, fontWeight:600, color:'var(--muted)', textTransform:'uppercase', letterSpacing:'0.06em', marginBottom:2 }}>{label}</div>
      <div style={{ fontSize:12, color:'var(--text)', fontFamily: mono ? 'JetBrains Mono, monospace' : 'inherit' }}>{value}</div>
    </div>
  )
}

function StatusToggle({ value, onChange }) {
  return (
    <div style={{ display:'flex', background:'var(--surface2)', border:'1px solid var(--border)', borderRadius:8, padding:3, gap:3 }}>
      {['FAIL','PASS',''].map(v => (
        <button key={v} onClick={() => onChange(v)} style={{
          padding:'5px 12px', borderRadius:6, border:'none', fontSize:12, fontWeight:500,
          background: value===v ? 'var(--accent)' : 'transparent',
          color: value===v ? '#fff' : 'var(--muted)',
          cursor:'pointer', transition:'all .15s',
        }}>{v || 'All'}</button>
      ))}
    </div>
  )
}

function FilterSelect({ value, onChange, placeholder, children }) {
  return (
    <select value={value} onChange={e => onChange(e.target.value)} style={{
      padding:'8px 12px', background:'var(--surface)', border:'1px solid var(--border)',
      borderRadius:8, color: value ? 'var(--text)' : 'var(--muted)',
      fontSize:13, outline:'none', cursor:'pointer',
    }}>
      <option value="">{placeholder}</option>
      {children}
    </select>
  )
}

function PageBtn({ children, onClick, disabled }) {
  return (
    <button onClick={onClick} disabled={disabled} style={{
      padding:'6px 14px', background:'var(--surface)', border:'1px solid var(--border)',
      borderRadius:8, color: disabled ? 'var(--muted)' : 'var(--text)',
      fontSize:12, cursor: disabled ? 'not-allowed' : 'pointer',
    }}>{children}</button>
  )
}

function SearchIcon({ style }) {
  return (
    <svg style={style} width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
      <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
    </svg>
  )
}
