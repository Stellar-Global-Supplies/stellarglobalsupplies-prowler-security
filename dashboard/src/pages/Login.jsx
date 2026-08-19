import { useEffect } from 'react'

const LANDING_URL = import.meta.env.VITE_LANDING_URL || 'https://apps.stellarglobalsupplies.com'

export default function Login() {
  useEffect(() => {
    const callback = encodeURIComponent(window.location.origin + '/')
    window.location.replace(`${LANDING_URL}/login?callback=${callback}`)
  }, [])

  return (
    <div style={{ minHeight:'100vh', display:'flex', alignItems:'center', justifyContent:'center', background:'var(--bg)', backgroundImage:'radial-gradient(ellipse 80% 60% at 50% -20%, #3b82f620, transparent)' }}>
      <div style={{ width:400, padding:'40px 36px', borderRadius:16, background:'var(--surface)', border:'1px solid var(--border)', boxShadow:'0 0 80px #3b82f610', textAlign:'center' }}>
        <ShieldIcon />
        <p style={{ color:'var(--muted)', fontSize:13, marginTop:16 }}>Redirecting to portal…</p>
      </div>
    </div>
  )
}

function ShieldIcon() {
  return (
    <svg width="40" height="40" viewBox="0 0 36 36" fill="none" style={{ margin:'0 auto' }}>
      <path d="M18 3L6 8v9c0 8.3 5.1 16.1 12 18 6.9-1.9 12-9.7 12-18V8L18 3z" fill="#3b82f620" stroke="#3b82f6" strokeWidth="1.5"/>
      <path d="M13 18l3.5 3.5L23 14" stroke="#3b82f6" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  )
}
