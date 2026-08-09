import { useEffect, useRef, useState, useCallback } from 'react'
import * as d3 from 'd3'
import { api } from '../lib/api'

const SEV_COLOR = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308',
  low: '#22c55e', unknown: '#64748b',
}
const SEV_GLOW = {
  critical: '#ef444460', high: '#f9731660', medium: '#eab30860',
  low: '#22c55e60', unknown: '#64748b40',
}
const SERVICE_ICONS = {
  s3:'🪣', iam:'👤', ec2:'💻', cloudflare:'🌐', dns:'🔤',
  worker:'⚡', d1:'🗄️', kv:'🔑', r2:'📦', access:'🔐',
  pages:'📄', default:'📦',
}

export default function AttackGraph() {
  const svgRef     = useRef(null)
  const tooltipRef = useRef(null)
  const simRef     = useRef(null)

  const [graphData, setGraphData] = useState({ nodes:[], edges:[] })
  const [loading, setLoading]     = useState(true)
  const [selected, setSelected]   = useState(null)
  const [filter, setFilter]       = useState('all')
  const [stats, setStats]         = useState({ nodes:0, edges:0, critical:0 })

  useEffect(() => {
    api.graph().then(data => {
      setGraphData(data)
      setStats({
        nodes: data.nodes?.length ?? 0,
        edges: data.edges?.length ?? 0,
        critical: data.nodes?.filter(n => n.severity === 'critical').length ?? 0,
      })
      setLoading(false)
    }).catch(() => setLoading(false))
  }, [])

  const buildGraph = useCallback(() => {
    if (!svgRef.current || !graphData.nodes?.length) return

    const el   = svgRef.current
    const W    = el.clientWidth  || 900
    const H    = el.clientHeight || 600

    d3.select(el).selectAll('*').remove()

    // Filter nodes
    const visibleNodes = filter === 'all'
      ? graphData.nodes
      : graphData.nodes.filter(n => n.severity === filter || n.findings > 0)

    const nodeIds = new Set(visibleNodes.map(n => n.id))
    const visibleEdges = graphData.edges.filter(
      e => nodeIds.has(e.source_id) && nodeIds.has(e.target_id)
    )

    if (visibleNodes.length === 0) return

    // Deep copy for D3 mutation
    const nodes = visibleNodes.map(n => ({ ...n }))
    const links = visibleEdges.map(e => ({
      ...e,
      source: e.source_id,
      target: e.target_id,
    }))

    const svg = d3.select(el)
    const defs = svg.append('defs')

    // Glow filter
    Object.entries(SEV_GLOW).forEach(([sev, color]) => {
      const f = defs.append('filter').attr('id', `glow-${sev}`).attr('x','-50%').attr('y','-50%').attr('width','200%').attr('height','200%')
      f.append('feGaussianBlur').attr('in','SourceGraphic').attr('stdDeviation',4).attr('result','blur')
      const merge = f.append('feMerge')
      merge.append('feMergeNode').attr('in','blur')
      merge.append('feMergeNode').attr('in','SourceSource')
    })

    // Arrow markers for edges
    const sevs = ['critical','high','medium','low','unknown']
    sevs.forEach(sev => {
      defs.append('marker')
        .attr('id', `arrow-${sev}`)
        .attr('viewBox','0 -5 10 10').attr('refX',22).attr('refY',0)
        .attr('markerWidth',6).attr('markerHeight',6).attr('orient','auto')
        .append('path').attr('d','M0,-5L10,0L0,5').attr('fill', SEV_COLOR[sev] ?? '#64748b').attr('opacity', 0.8)
    })

    // Background
    svg.append('rect').attr('width', W).attr('height', H).attr('fill','transparent')

    const g = svg.append('g')

    // Zoom
    svg.call(
      d3.zoom().scaleExtent([0.2, 4])
        .on('zoom', e => g.attr('transform', e.transform))
    )

    // Force simulation
    const sim = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(links).id(d => d.id).distance(d => {
        const s = d.severity
        return s === 'critical' ? 80 : s === 'high' ? 100 : 130
      }).strength(0.5))
      .force('charge', d3.forceManyBody().strength(-280))
      .force('center', d3.forceCenter(W / 2, H / 2))
      .force('collision', d3.forceCollide().radius(36))

    simRef.current = sim

    // Links
    const link = g.append('g').selectAll('line').data(links).enter().append('line')
      .attr('stroke', d => SEV_COLOR[d.severity] ?? '#64748b')
      .attr('stroke-opacity', 0.5)
      .attr('stroke-width', d => d.severity === 'critical' ? 2 : 1.5)
      .attr('stroke-dasharray', d => d.severity === 'low' ? '4,4' : null)
      .attr('marker-end', d => `url(#arrow-${d.severity ?? 'unknown'})`)

    // Link labels
    const linkLabel = g.append('g').selectAll('text').data(links).enter().append('text')
      .attr('fill', '#64748b').attr('font-size', 9).attr('text-anchor','middle')
      .attr('font-family','Inter, sans-serif').attr('pointer-events','none')
      .text(d => d.relationship ?? '')

    // Node groups
    const node = g.append('g').selectAll('g').data(nodes).enter().append('g')
      .style('cursor','pointer')
      .call(
        d3.drag()
          .on('start', (e, d) => { if (!e.active) sim.alphaTarget(0.3).restart(); d.fx=d.x; d.fy=d.y })
          .on('drag',  (e, d) => { d.fx=e.x; d.fy=e.y })
          .on('end',   (e, d) => { if (!e.active) sim.alphaTarget(0); d.fx=null; d.fy=null })
      )
      .on('click', (e, d) => { e.stopPropagation(); setSelected(d) })

    // Outer glow ring (for nodes with findings)
    node.filter(d => d.findings > 0).append('circle')
      .attr('r', d => 22 + (d.findings > 5 ? 4 : 0))
      .attr('fill','none')
      .attr('stroke', d => SEV_COLOR[d.severity] ?? '#64748b')
      .attr('stroke-width', 1.5)
      .attr('stroke-opacity', 0.4)
      .attr('filter', d => `url(#glow-${d.severity ?? 'unknown'})`)

    // Main circle
    node.append('circle')
      .attr('r', d => d.findings > 0 ? 20 : 16)
      .attr('fill', d => {
        const c = SEV_COLOR[d.severity] ?? '#1e2535'
        return d.findings > 0 ? `${c}20` : 'var(--surface2)'
      })
      .attr('stroke', d => d.findings > 0 ? (SEV_COLOR[d.severity] ?? '#64748b') : 'var(--border2)')
      .attr('stroke-width', 2)

    // Icon
    node.append('text')
      .attr('text-anchor','middle').attr('dominant-baseline','central')
      .attr('font-size', 14)
      .text(d => SERVICE_ICONS[d.service?.toLowerCase()] ?? SERVICE_ICONS.default)

    // Findings badge
    node.filter(d => d.findings > 0).append('circle')
      .attr('cx', 14).attr('cy', -14).attr('r', 9)
      .attr('fill', d => SEV_COLOR[d.severity] ?? '#64748b')
      .attr('stroke','var(--bg)').attr('stroke-width',2)

    node.filter(d => d.findings > 0).append('text')
      .attr('x',14).attr('y',-14)
      .attr('text-anchor','middle').attr('dominant-baseline','central')
      .attr('font-size', 8).attr('font-weight',700).attr('fill','#fff')
      .attr('font-family','JetBrains Mono, monospace')
      .text(d => d.findings > 99 ? '99+' : d.findings)

    // Label
    node.append('text')
      .attr('y', d => (d.findings > 0 ? 20 : 16) + 12)
      .attr('text-anchor','middle').attr('font-size', 10)
      .attr('fill','var(--muted)').attr('font-family','Inter, sans-serif')
      .text(d => truncate(d.label ?? d.service ?? '', 14))

    // Tooltip div
    const tip = d3.select(tooltipRef.current)
    node
      .on('mouseenter', (e, d) => {
        tip.style('opacity',1)
          .html(`
            <div style="font-weight:600;margin-bottom:4px">${d.label ?? d.service}</div>
            <div style="font-size:11px;color:#64748b;margin-bottom:6px">${d.provider?.toUpperCase()} · ${d.service?.toUpperCase()}</div>
            ${d.findings > 0
              ? `<div style="color:${SEV_COLOR[d.severity]}">⚠ ${d.findings} finding${d.findings>1?'s':''} · ${d.severity}</div>`
              : '<div style="color:#22c55e">✓ No open issues</div>'
            }
            ${d.region ? `<div style="font-size:11px;color:#64748b;margin-top:4px">${d.region}</div>` : ''}
          `)
      })
      .on('mousemove', e => {
        tip.style('left', (e.offsetX + 16)+'px').style('top', (e.offsetY - 10)+'px')
      })
      .on('mouseleave', () => tip.style('opacity', 0))

    // Click away to deselect
    svg.on('click', () => setSelected(null))

    // Tick
    sim.on('tick', () => {
      link
        .attr('x1', d => d.source.x).attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x).attr('y2', d => d.target.y)
      linkLabel
        .attr('x', d => (d.source.x + d.target.x) / 2)
        .attr('y', d => (d.source.y + d.target.y) / 2 - 5)
      node.attr('transform', d => `translate(${d.x},${d.y})`)
    })
  }, [graphData, filter])

  useEffect(() => { buildGraph() }, [buildGraph])

  // Redraw on resize
  useEffect(() => {
    const ro = new ResizeObserver(() => buildGraph())
    if (svgRef.current) ro.observe(svgRef.current)
    return () => ro.disconnect()
  }, [buildGraph])

  return (
    <div style={{ height:'calc(100vh - 56px)', display:'flex', flexDirection:'column' }}>
      {/* Header */}
      <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:16 }}>
        <div>
          <h1 style={{ fontSize:22, fontWeight:700, letterSpacing:'-0.03em', marginBottom:2 }}>Attack Graph</h1>
          <p style={{ color:'var(--muted)', fontSize:13 }}>
            {stats.nodes} resources · {stats.edges} connections · {stats.critical} critical nodes
          </p>
        </div>

        {/* Filter chips */}
        <div style={{ display:'flex', gap:6 }}>
          {['all','critical','high','medium','low'].map(f => (
            <button key={f} onClick={() => setFilter(f)} style={{
              padding:'5px 12px', borderRadius:20, border:'1px solid',
              borderColor: filter===f ? (SEV_COLOR[f] ?? 'var(--accent)') : 'var(--border)',
              background: filter===f ? `${SEV_COLOR[f] ?? 'var(--accent)'}20` : 'transparent',
              color: filter===f ? (SEV_COLOR[f] ?? 'var(--accent)') : 'var(--muted)',
              fontSize:12, fontWeight:500, cursor:'pointer', textTransform:'capitalize',
              transition:'all .15s',
            }}>{f}</button>
          ))}
        </div>
      </div>

      {/* Graph area */}
      <div style={{ flex:1, position:'relative', background:'var(--surface)', border:'1px solid var(--border)', borderRadius:12, overflow:'hidden' }}>
        {loading && (
          <div style={{ position:'absolute', inset:0, display:'flex', alignItems:'center', justifyContent:'center', color:'var(--muted)', fontSize:13, zIndex:2 }}>
            Loading attack graph…
          </div>
        )}

        {!loading && graphData.nodes?.length === 0 && (
          <div style={{ position:'absolute', inset:0, display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center', color:'var(--muted)', gap:8 }}>
            <div style={{ fontSize:32 }}>🔍</div>
            <div style={{ fontSize:14, fontWeight:500 }}>No graph data yet</div>
            <div style={{ fontSize:12 }}>Run a Prowler scan to populate the attack graph</div>
          </div>
        )}

        {/* D3 SVG */}
        <svg ref={svgRef} style={{ width:'100%', height:'100%', display:'block' }} />

        {/* Hover tooltip */}
        <div ref={tooltipRef} style={{
          position:'absolute', pointerEvents:'none', opacity:0,
          background:'var(--surface2)', border:'1px solid var(--border2)',
          borderRadius:8, padding:'10px 14px', fontSize:12, color:'var(--text)',
          boxShadow:'0 8px 24px #00000040', maxWidth:220,
          transition:'opacity .1s', zIndex:10,
        }} />

        {/* Legend */}
        <div style={{
          position:'absolute', bottom:16, left:16,
          background:'var(--surface2)', border:'1px solid var(--border)',
          borderRadius:10, padding:'12px 14px', fontSize:11,
        }}>
          <div style={{ fontWeight:600, marginBottom:8, color:'var(--muted)', textTransform:'uppercase', letterSpacing:'0.06em' }}>Legend</div>
          {Object.entries(SEV_COLOR).filter(([s])=>s!=='unknown').map(([sev, color]) => (
            <div key={sev} style={{ display:'flex', alignItems:'center', gap:7, marginBottom:5 }}>
              <div style={{ width:8, height:8, borderRadius:'50%', background:color, boxShadow:`0 0 6px ${color}` }} />
              <span style={{ color:'var(--muted)', textTransform:'capitalize' }}>{sev}</span>
            </div>
          ))}
          <div style={{ borderTop:'1px solid var(--border)', marginTop:8, paddingTop:8, color:'var(--muted)' }}>
            <div style={{ display:'flex', alignItems:'center', gap:7, marginBottom:4 }}>
              <div style={{ width:16, height:0, borderTop:'1.5px solid #64748b' }} />
              <span>Connection</span>
            </div>
            <div style={{ display:'flex', alignItems:'center', gap:7 }}>
              <div style={{ width:16, height:0, borderTop:'1.5px dashed #64748b' }} />
              <span>Low-risk path</span>
            </div>
          </div>
        </div>

        {/* Controls hint */}
        <div style={{
          position:'absolute', bottom:16, right:16, fontSize:11, color:'var(--muted)',
          background:'var(--surface2)', border:'1px solid var(--border)',
          borderRadius:8, padding:'8px 12px', lineHeight:1.8,
        }}>
          <div>Scroll to zoom</div>
          <div>Drag to pan</div>
          <div>Click node for details</div>
        </div>
      </div>

      {/* Selected node detail panel */}
      {selected && (
        <NodeDetail node={selected} onClose={() => setSelected(null)} />
      )}
    </div>
  )
}

function NodeDetail({ node, onClose }) {
  const color = SEV_COLOR[node.severity] ?? '#64748b'
  return (
    <div style={{
      position:'fixed', right:24, top:'50%', transform:'translateY(-50%)',
      width:300, background:'var(--surface)', border:`1px solid ${color}40`,
      borderRadius:12, padding:20, boxShadow:`0 0 40px ${color}20`, zIndex:100,
    }}>
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', marginBottom:16 }}>
        <div>
          <div style={{ fontSize:11, color:'var(--muted)', textTransform:'uppercase', letterSpacing:'0.06em', marginBottom:4 }}>
            {node.provider?.toUpperCase()} · {node.service?.toUpperCase()}
          </div>
          <div style={{ fontSize:15, fontWeight:600 }}>{node.label}</div>
        </div>
        <button onClick={onClose} style={{ background:'none', border:'none', color:'var(--muted)', fontSize:18, cursor:'pointer', padding:'0 4px' }}>×</button>
      </div>

      {/* Risk score */}
      <div style={{ display:'flex', gap:12, marginBottom:16 }}>
        <div style={{ flex:1, background:`${color}15`, border:`1px solid ${color}30`, borderRadius:8, padding:'10px 12px', textAlign:'center' }}>
          <div style={{ fontSize:20, fontWeight:700, color, fontFamily:'JetBrains Mono, monospace' }}>{node.findings ?? 0}</div>
          <div style={{ fontSize:10, color:'var(--muted)', textTransform:'uppercase', letterSpacing:'0.05em' }}>Findings</div>
        </div>
        <div style={{ flex:1, background:'var(--surface2)', border:'1px solid var(--border)', borderRadius:8, padding:'10px 12px', textAlign:'center' }}>
          <div style={{ fontSize:20, fontWeight:700, color, textTransform:'capitalize', fontFamily:'JetBrains Mono, monospace' }}>{node.severity ?? '—'}</div>
          <div style={{ fontSize:10, color:'var(--muted)', textTransform:'uppercase', letterSpacing:'0.05em' }}>Severity</div>
        </div>
      </div>

      <div style={{ fontSize:12, color:'var(--muted)', display:'flex', flexDirection:'column', gap:6 }}>
        {[
          ['Resource ID', node.id],
          ['Region',      node.region ?? 'global'],
          ['Risk Score',  node.risk ?? 0],
        ].map(([k,v]) => (
          <div key={k} style={{ display:'flex', justifyContent:'space-between', padding:'4px 0', borderBottom:'1px solid var(--border)' }}>
            <span>{k}</span>
            <span style={{ color:'var(--text)', fontFamily:'JetBrains Mono, monospace', fontSize:11, maxWidth:160, overflow:'hidden', textOverflow:'ellipsis' }}>{v}</span>
          </div>
        ))}
      </div>

      {node.findings > 0 && (
        <div style={{ marginTop:14, padding:'10px 12px', background:'var(--critical-bg)', border:'1px solid var(--critical)30', borderRadius:8, fontSize:12, color:'var(--critical)' }}>
          ⚠ This resource has open security findings. View in Findings tab.
        </div>
      )}
    </div>
  )
}

function truncate(str, len) {
  return str.length > len ? str.slice(0, len) + '…' : str
}
