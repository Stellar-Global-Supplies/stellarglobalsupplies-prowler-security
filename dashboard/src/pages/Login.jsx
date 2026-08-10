import { useState } from 'react'
import { supabase } from '../lib/supabase'

const s = {
  wrap: {
    minHeight:'100vh', display:'flex', alignItems:'center', justifyContent:'center',
    background:'var(--bg)',
    backgroundImage:'radial-gradient(ellipse 80% 60% at 50% -20%, #3b82f620, transparent)',
  },
  card: {
    width: 400, padding: '40px 36px', borderRadius: 16,
    background:'var(--surface)', border:'1px solid var(--border)',
    boxShadow:'0 0 80px #3b82f610',
  },
  logo: {
    display:'flex', alignItems:'center', gap:10, marginBottom:32,
  },
  shield: { width:36, height:36 },
  brand: { fontSize:20, fontWeight:700, letterSpacing:'-0.02em' },
  sub: { color:'var(--muted)', fontSize:13, marginBottom:32 },
  label: { display:'block', fontSize:12, fontWeight:500, color:'var(--muted)', marginBottom:6, letterSpacing:'0.04em', textTransform:'uppercase' },
  input: {
    width:'100%', padding:'10px 14px', background:'var(--surface2)',
    border:'1px solid var(--border2)', borderRadius:8, color:'var(--text)',
    fontSize:14, outline:'none', marginBottom:16,
    transition:'border-color .15s',
  },
  btn: {
    width:'100%', padding:'11px', background:'var(--accent)', border:'none',
    borderRadius:8, color:'#fff', fontSize:14, fontWeight:600, marginTop:4,
    transition:'opacity .15s',
  },
  divider: { display:'flex', alignItems:'center', gap:12, margin:'20px 0', color:'var(--muted)', fontSize:12 },
  line: { flex:1, height:1, background:'var(--border)' },
  oauthBtn: {
    width:'100%', padding:'10px', background:'var(--surface2)',
    border:'1px solid var(--border2)', borderRadius:8, color:'var(--text)',
    fontSize:13, fontWeight:500, display:'flex', alignItems:'center',
    justifyContent:'center', gap:8, marginBottom:8,
  },
  error: { color:'var(--critical)', fontSize:13, marginBottom:12, background:'var(--critical-bg)', padding:'8px 12px', borderRadius:6 },
  toggle: { textAlign:'center', marginTop:20, fontSize:13, color:'var(--muted)' },
  link: { color:'var(--accent)', cursor:'pointer', fontWeight:500 },
}

export default function Login() {
  const [email, setEmail]     = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError]     = useState('')

  async function handleSubmit(e) {
    e.preventDefault()
    setLoading(true); setError('')
    const { error: err } = await supabase.auth.signInWithPassword({ email, password })
    if (err) setError(err.message)
    setLoading(false)
  }

  async function handleGitHub() {
    await supabase.auth.signInWithOAuth({
      provider: 'github',
      options: { redirectTo: window.location.origin },
    })
  }

  return (
    <div style={s.wrap}>
      <div style={s.card}>
        <div style={s.logo}>
          <ShieldIcon style={s.shield} />
          <div>
            <span style={s.brand}>Stellar Security View</span>
            <div style={{ fontSize:11, color:'var(--muted)', marginTop:2 }}>Powered by Prowler</div>
          </div>
        </div>
        <p style={s.sub}>
          Sign in to Stellar Security View
        </p>

        {error && <div style={s.error}>{error}</div>}

        <form onSubmit={handleSubmit}>
          <label style={s.label}>Email</label>
          <input
            style={s.input} type="email" value={email} required
            placeholder="you@company.com"
            onChange={e => setEmail(e.target.value)}
            onFocus={e => e.target.style.borderColor = 'var(--accent)'}
            onBlur={e => e.target.style.borderColor = 'var(--border2)'}
          />
          <label style={s.label}>Password</label>
          <input
            style={s.input} type="password" value={password} required
            placeholder="••••••••"
            onChange={e => setPassword(e.target.value)}
            onFocus={e => e.target.style.borderColor = 'var(--accent)'}
            onBlur={e => e.target.style.borderColor = 'var(--border2)'}
          />
          <button style={s.btn} disabled={loading}>
            {loading ? 'Please wait…' : 'Sign in'}
          </button>
        </form>

        <div style={s.divider}>
          <div style={s.line}/> or <div style={s.line}/>
        </div>

        <button style={s.oauthBtn} onClick={handleGitHub}>
          <GitHubIcon /> Continue with GitHub
        </button>
      </div>
    </div>
  )
}

function ShieldIcon({ style }) {
  return (
    <svg style={style} viewBox="0 0 36 36" fill="none">
      <path d="M18 3L6 8v9c0 8.3 5.1 16.1 12 18 6.9-1.9 12-9.7 12-18V8L18 3z" fill="#3b82f620" stroke="#3b82f6" strokeWidth="1.5"/>
      <path d="M13 18l3.5 3.5L23 14" stroke="#3b82f6" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  )
}

function GitHubIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
      <path d="M12 0C5.37 0 0 5.37 0 12c0 5.3 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 21.795 24 17.295 24 12c0-6.63-5.37-12-12-12"/>
    </svg>
  )
}
