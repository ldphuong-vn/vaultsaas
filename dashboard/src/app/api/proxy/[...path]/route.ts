import { cookies } from 'next/headers'
import { NextRequest, NextResponse } from 'next/server'
import { backendUrl } from '@/lib/backend'

// Forward a request to the backend with the given access token.
// Body is passed explicitly so it can be reused across retry attempts.
// The catch-all path is user-controlled, so it goes through backendUrl's
// segment validation — the target origin stays fixed at BACKEND_URL.
async function forwardToBackend(
  req: NextRequest,
  path: string,
  token: string,
  body: string | undefined,
): Promise<Response> {
  const url = new URL(req.url)
  let target: URL
  try {
    target = backendUrl(path, url.search)
  } catch {
    return new NextResponse(JSON.stringify({ error: 'Invalid path' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    })
  }

  const headers: HeadersInit = {
    Authorization: `Bearer ${token}`,
    'Content-Type': 'application/json',
  }

  return fetch(target, { method: req.method, headers, body })
}

// Attempt to refresh the access token using the refresh token cookie.
// Returns new token strings on success, null on failure.
async function tryRefreshTokens(refreshToken: string): Promise<{
  access_token: string
  refresh_token: string
  expires_in: number
} | null> {
  try {
    const res = await fetch(backendUrl('/auth/refresh'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refreshToken }),
    })
    if (!res.ok) return null
    return res.json()
  } catch {
    return null
  }
}

// Set auth cookies on a NextResponse.
function setAuthCookies(
  res: NextResponse,
  accessToken: string,
  refreshToken: string,
  expiresIn: number,
): void {
  const secure = process.env.NODE_ENV === 'production'
  res.cookies.set('valt_access_token', accessToken, {
    httpOnly: true,
    secure,
    sameSite: 'lax',
    path: '/',
    maxAge: expiresIn,
  })
  res.cookies.set('valt_refresh_token', refreshToken, {
    httpOnly: true,
    secure,
    sameSite: 'lax',
    path: '/',
    maxAge: 7 * 24 * 60 * 60,
  })
}

async function proxyRequest(req: NextRequest, params: { path: string[] }) {
  const cookieStore = await cookies()
  const token = cookieStore.get('valt_access_token')?.value
  const refreshToken = cookieStore.get('valt_refresh_token')?.value

  // No tokens at all — reject immediately.
  if (!token && !refreshToken) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  const path = params.path.join('/')

  // Read body once here so it can be reused for retry after token refresh.
  const requestBody =
    req.method !== 'GET' && req.method !== 'HEAD' ? await req.text() : undefined

  // Try the request with the current access token.
  if (token) {
    const backendRes = await forwardToBackend(req, path, token, requestBody)
    if (backendRes.status !== 401) {
      const data = await backendRes.text()
      return new NextResponse(data, {
        status: backendRes.status,
        headers: { 'Content-Type': backendRes.headers.get('Content-Type') ?? 'application/json' },
      })
    }
  }

  // Access token missing or expired — attempt silent refresh.
  if (!refreshToken) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  const newTokens = await tryRefreshTokens(refreshToken)
  if (!newTokens) {
    // Refresh failed — clear cookies and signal client to re-login.
    const errRes = NextResponse.json({ error: 'Session expired' }, { status: 401 })
    errRes.cookies.delete('valt_access_token')
    errRes.cookies.delete('valt_refresh_token')
    return errRes
  }

  // Retry the original request with the refreshed access token.
  // requestBody was read above before the first attempt, so it's safe to reuse.
  const retryRes = await forwardToBackend(req, path, newTokens.access_token, requestBody)
  const retryData = await retryRes.text()

  const response = new NextResponse(retryData, {
    status: retryRes.status,
    headers: { 'Content-Type': retryRes.headers.get('Content-Type') ?? 'application/json' },
  })

  // Attach rotated tokens to the response so the browser cookie jar is updated.
  setAuthCookies(response, newTokens.access_token, newTokens.refresh_token, newTokens.expires_in)
  return response
}

export async function GET(req: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  return proxyRequest(req, await params)
}
export async function POST(req: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  return proxyRequest(req, await params)
}
export async function PUT(req: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  return proxyRequest(req, await params)
}
export async function DELETE(req: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  return proxyRequest(req, await params)
}
