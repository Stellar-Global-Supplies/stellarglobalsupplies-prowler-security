import { useEffect, useState } from 'react'
import { supabase } from '../lib/supabase'

const EXCHANGE_FN = `${import.meta.env.VITE_SUPABASE_URL}/functions/v1/sso-exchange`
const LANDING_URL =
  import.meta.env.VITE_LANDING_URL || 'https://apps.stellarglobalsupplies.com'

const MAX_AGE_MS = 5 * 60 * 1000

// ── Open-redirect guard ───────────────────────────────────────
// Only allow same-origin paths.
// External URLs fall back to the application root.
function safeRedirect(redirect, fallback = '/') {
  try {
    const url = new URL(redirect, window.location.origin)

    if (url.origin !== window.location.origin) {
      return fallback
    }

    return url.pathname + url.search + url.hash
  } catch {
    return fallback
  }
}

export default function SSOCallback() {
  const [status, setStatus] = useState('Verifying your session…')
  const [error, setError] = useState(null)

  useEffect(() => {
    const params = new URLSearchParams(window.location.search)

    const token = params.get('token')

    // Never use the raw redirect parameter.
    const redirect = safeRedirect(
      params.get('redirect') || '/'
    )

    /*
     * IMPORTANT:
     * Requests without a token are sent back to the portal
     * BEFORE timestamp validation.
     */
    if (!token) {
      const callback = encodeURIComponent(
        window.location.origin + redirect
      )

      window.location.replace(
        `${LANDING_URL}/login?callback=${callback}`
      )

      return
    }

    /*
     * A token is present, so ts is mandatory.
     */
    const tsRaw = params.get('ts')

    if (!tsRaw) {
      setError(
        'This sign-in link is invalid. Please return to the portal.'
      )
      return
    }

    const ts = Number(tsRaw)

    /*
     * Reject:
     * - NaN
     * - Infinity
     * - -Infinity
     * - zero
     * - negative timestamps
     */
    if (!Number.isFinite(ts) || ts <= 0) {
      setError(
        'This sign-in link is invalid. Please return to the portal.'
      )
      return
    }

    const now = Date.now()

    /*
     * Reject timestamps from the future.
     */
    if (ts > now) {
      setError(
        'This sign-in link is invalid. Please return to the portal.'
      )
      return
    }

    /*
     * Reject timestamps older than 5 minutes.
     */
    if (now - ts > MAX_AGE_MS) {
      setError(
        'This sign-in link has expired. Please return to the portal.'
      )
      return
    }

    setStatus('Exchanging credentials…')

    fetch(EXCHANGE_FN, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ token }),
    })
      .then(async res => {
        const data = await res.json()

        if (!res.ok) {
          throw new Error(
            data.error || `Exchange failed (${res.status})`
          )
        }

        return data
      })
      .then(async ({ access_token, refresh_token }) => {
        setStatus('Setting up your workspace…')

        const { error: authErr } =
          await supabase.auth.setSession({
            access_token,
            refresh_token,
          })

        if (authErr) {
          throw new Error(authErr.message)
        }

        // Redirect has already been validated by safeRedirect().
        window.location.replace(redirect)
      })
      .catch(err => {
        setError(
          err?.message ||
            'Sign-in failed. Please return to the portal.'
        )
      })
  }, [])

  const s = {
    wrap: {
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: 'var(--bg)',
      backgroundImage:
        'radial-gradient(ellipse 80% 60% at 50% -20%, #3b82f620, transparent)',
    },

    card: {
      width: 400,
      padding: '40px 36px',
      borderRadius: 16,
      background: 'var(--surface)',
      border: '1px solid var(--border)',
      boxShadow: '0 0 80px #3b82f610',
      textAlign: 'center',
    },

    logo: {
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      gap: 10,
      marginBottom: 24,
    },

    brand: {
      fontSize: 18,
      fontWeight: 700,
      letterSpacing: '-0.02em',
    },

    btn: {
      display: 'inline-block',
      marginTop: 16,
      padding: '10px 28px',
      background: 'var(--accent)',
      borderRadius: 8,
      color: '#fff',
      fontSize: 14,
      fontWeight: 600,
      textDecoration: 'none',
    },
  }

  if (error) {
    return (
      <div style={s.wrap}>
        <div style={s.card}>
          <div style={s.logo}>
            <ShieldIcon />
            <span style={s.brand}>
              Stellar Security View
            </span>
          </div>

          <p
            style={{
              color: 'var(--critical)',
              fontWeight: 600,
              marginBottom: 8,
            }}
          >
            Sign-in error
          </p>

          <p
            style={{
              color: 'var(--muted)',
              fontSize: 13,
              marginBottom: 4,
            }}
          >
            {error}
          </p>

          <a href={LANDING_URL} style={s.btn}>
            Return to Portal
          </a>
        </div>
      </div>
    )
  }

  return (
    <div style={s.wrap}>
      <div style={s.card}>
        <div style={s.logo}>
          <ShieldIcon />
          <span style={s.brand}>
            Stellar Security View
          </span>
        </div>

        <Spinner />

        <p
          style={{
            color: 'var(--muted)',
            fontSize: 13,
            marginTop: 16,
          }}
        >
          {status}
        </p>
      </div>
    </div>
  )
}

function ShieldIcon() {
  return (
    <svg
      width="32"
      height="32"
      viewBox="0 0 36 36"
      fill="none"
    >
      <path
        d="M18 3L6 8v9c0 8.3 5.1 16.1 12 18 6.9-1.9 12-9.7 12-18V8L18 3z"
        fill="#3b82f620"
        stroke="#3b82f6"
        strokeWidth="1.5"
      />

      <path
        d="M13 18l3.5 3.5L23 14"
        stroke="#3b82f6"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}

function Spinner() {
  return (
    <svg
      width="32"
      height="32"
      viewBox="0 0 32 32"
      style={{
        animation: 'spin 1s linear infinite',
        margin: '0 auto',
      }}
    >
      <style>{`
        @keyframes spin {
          to {
            transform: rotate(360deg);
          }
        }
      `}</style>

      <circle
        cx="16"
        cy="16"
        r="12"
        fill="none"
        stroke="var(--border2)"
        strokeWidth="3"
      />

      <path
        d="M16 4 A12 12 0 0 1 28 16"
        fill="none"
        stroke="var(--accent)"
        strokeWidth="3"
        strokeLinecap="round"
      />
    </svg>
  )
}
