import { cookies } from 'next/headers'
import { NextResponse } from 'next/server'
import { backendUrl } from '@/lib/backend'

// POST /api/auth/refresh
// Reads valt_refresh_token cookie, calls backend refresh, sets new httpOnly cookies.
// Used by client-side apiFetch as a fallback before redirecting to login.
export async function POST() {
  const cookieStore = await cookies()
  const refreshToken = cookieStore.get('valt_refresh_token')?.value

  if (!refreshToken) {
    return NextResponse.json({ error: 'No refresh token' }, { status: 401 })
  }

  const backendRes = await fetch(backendUrl('/auth/refresh'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refresh_token: refreshToken }),
  }).catch(() => null)

  if (!backendRes || !backendRes.ok) {
    // Clear stale cookies on refresh failure
    const errRes = NextResponse.json({ error: 'Session expired' }, { status: 401 })
    errRes.cookies.delete('valt_access_token')
    errRes.cookies.delete('valt_refresh_token')
    return errRes
  }

  const tokens = await backendRes.json() as {
    access_token: string
    refresh_token: string
    expires_in: number
  }

  const res = NextResponse.json({ ok: true })
  res.cookies.set('valt_access_token', tokens.access_token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
    maxAge: tokens.expires_in ?? 900,
  })
  res.cookies.set('valt_refresh_token', tokens.refresh_token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
    maxAge: 7 * 24 * 60 * 60,
  })
  return res
}
