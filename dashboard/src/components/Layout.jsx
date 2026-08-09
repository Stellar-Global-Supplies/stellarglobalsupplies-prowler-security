import { useLocation, useNavigate, Link } from 'react-router-dom'
import { supabase } from '../lib/supabase'

const NAV = [
  { path: '/',             label: 'Overview',     icon: HomeIcon },
  { path: '/findings',     label: 'Findings',     icon: FindingsIcon },
  { path: '/attack-graph', label: 'Attack Graph', icon: GraphIcon },
]

export default function Layout({ children }) {
  const loc = useLocation()
  const navigate = useNavigate()

  async function signOut() {
    await supabase.auth.signOut()
    navigate('/')
  }

  return (
    <div style={{ display:'flex', height:'100vh', overflow:'hidden' }}>
      {/* Sidebar */}
      <aside style={{
        width: 220, flexShrink: 0, background:'var(--surface)',
        borderRight:'1px solid var(--border)', display:'flex',
        flexDirection:'column', padding:'20px 0',
      }}>
        {/* Logo */}
        <div style={{ padding:'0 20px 24px', borderBottom:'1px solid var(--border)' }}>
          <div style={{ display:'flex', alignItems:'center', gap:10 }}>
            <ShieldLogo />
            <div>
              <div style={{ fontSize:15, fontWeight:700, letterSpacing:'-0.02em' }}>Stellar Security View</div>
              <div style={{ fontSize:11, color:'var(--muted)' }}>Powered by Prowler</div>
            </div>
          </div>
        </div>

        {/* Provider badges */}
        <div style={{ padding:'16px 20px', borderBottom:'1px solid var(--border)' }}>
          <div style={{ fontSize:11, fontWeight:500, color:'var(--muted)', marginBottom:8, textTransform:'uppercase', letterSpacing:'0.06em' }}>Providers</div>
          <div style={{ display:'flex', flexDirection:'column', gap:4 }}>
            <ProviderBadge label="AWS" color="#f97316" />
            <ProviderBadge label="Cloudflare" color="#f6821f" />
          </div>
        </div>

        {/* Nav */}
        <nav style={{ flex:1, padding:'12px 12px' }}>
          {NAV.map(({ path, label, icon: Icon }) => {
            const active = loc.pathname === path
            return (
              <Link key={path} to={path} style={{
                display:'flex', alignItems:'center', gap:10,
                padding:'9px 12px', borderRadius:8, marginBottom:2,
                color: active ? '#fff' : 'var(--muted)',
                background: active ? 'var(--accent-glow)' : 'transparent',
                borderLeft: active ? '2px solid var(--accent)' : '2px solid transparent',
                fontWeight: active ? 500 : 400,
                fontSize: 13,
                transition:'all .15s',
              }}>
                <Icon size={16} color={active ? 'var(--accent)' : 'var(--muted)'} />
                {label}
              </Link>
            )
          })}
        </nav>

        {/* Sign out */}
        <div style={{ padding:'16px 12px', borderTop:'1px solid var(--border)' }}>
          <button onClick={signOut} style={{
            width:'100%', padding:'8px 12px', background:'transparent',
            border:'1px solid var(--border)', borderRadius:8,
            color:'var(--muted)', fontSize:13, display:'flex',
            alignItems:'center', gap:8, transition:'all .15s',
          }}
            onMouseEnter={e => { e.currentTarget.style.borderColor='var(--critical)'; e.currentTarget.style.color='var(--critical)' }}
            onMouseLeave={e => { e.currentTarget.style.borderColor='var(--border)'; e.currentTarget.style.color='var(--muted)' }}
          >
            <LogoutIcon size={14} /> Sign out
          </button>
        </div>
      </aside>

      {/* Main */}
      <main style={{ flex:1, overflowY:'auto', padding:'28px 32px', background:'var(--bg)' }}>
        {children}
      </main>
    </div>
  )
}

function ProviderBadge({ label, color }) {
  return (
    <div style={{ display:'flex', alignItems:'center', gap:8, padding:'4px 8px', background:'var(--surface2)', borderRadius:6, border:'1px solid var(--border)' }}>
      <div style={{ width:6, height:6, borderRadius:'50%', background:color, boxShadow:`0 0 6px ${color}` }} />
      <span style={{ fontSize:12, color:'var(--text)' }}>{label}</span>
      <span style={{ marginLeft:'auto', fontSize:10, color:'var(--pass)', background:'#10b98115', padding:'1px 5px', borderRadius:4 }}>LIVE</span>
    </div>
  )
}

function ShieldLogo() {
  return (
    <svg width="32" height="32" viewBox="0 0 32 32" fill="none">
      <path d="M16 2L4 7v8c0 7.4 5.1 14.3 12 16 6.9-1.7 12-8.6 12-16V7L16 2z" fill="#3b82f625" stroke="#3b82f6" strokeWidth="1.5"/>
      <path d="M11 16l3.5 3.5L21 12" stroke="#3b82f6" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  )
}

function HomeIcon({ size, color }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round"><path d="M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>
}
function FindingsIcon({ size, color }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/><line x1="11" y1="8" x2="11" y2="14"/><line x1="8" y1="11" x2="14" y2="11"/></svg>
}
function GraphIcon({ size, color }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>
}
function LogoutIcon({ size }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
}
