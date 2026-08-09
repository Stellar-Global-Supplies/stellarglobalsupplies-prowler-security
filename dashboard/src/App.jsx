import { useEffect, useState } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { supabase } from './lib/supabase'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Findings from './pages/Findings'
import AttackGraph from './pages/AttackGraph'
import Layout from './components/Layout'

export default function App() {
  const [session, setSession] = useState(undefined) // undefined = loading

  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => setSession(data.session))
    const { data: { subscription } } = supabase.auth.onAuthStateChange((_e, s) => setSession(s))
    return () => subscription.unsubscribe()
  }, [])

  if (session === undefined) {
    return (
      <div style={{ display:'flex', alignItems:'center', justifyContent:'center', height:'100vh', background:'var(--bg)' }}>
        <Spinner />
      </div>
    )
  }

  if (!session) return <Login />

  return (
    <Layout>
      <Routes>
        <Route path="/"             element={<Dashboard />} />
        <Route path="/findings"     element={<Findings />} />
        <Route path="/attack-graph" element={<AttackGraph />} />
        <Route path="*"             element={<Navigate to="/" />} />
      </Routes>
    </Layout>
  )
}

function Spinner() {
  return (
    <svg width="32" height="32" viewBox="0 0 32 32" style={{ animation:'spin 1s linear infinite' }}>
      <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>
      <circle cx="16" cy="16" r="12" fill="none" stroke="var(--border2)" strokeWidth="3"/>
      <path d="M16 4 A12 12 0 0 1 28 16" fill="none" stroke="var(--accent)" strokeWidth="3" strokeLinecap="round"/>
    </svg>
  )
}
