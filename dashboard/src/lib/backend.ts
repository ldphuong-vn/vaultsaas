// Shared builder for backend API URLs used by server components and route
// handlers. The backend origin always comes from BACKEND_URL (operator
// config); user-controlled input may only contribute path segments. Segments
// are individually validated and encoded, so a request can never be pointed
// at another origin and traversal characters cannot alter the target path.
const BACKEND = process.env.BACKEND_URL ?? 'http://localhost:8080'

export class BackendPathError extends Error {}

export function backendUrl(path: string, search = ''): URL {
  const segments = path.split('/').filter((s) => s.length > 0)
  for (const segment of segments) {
    if (segment === '..' || segment === '.' || segment.includes('\\') || /[\r\n\0]/.test(segment)) {
      throw new BackendPathError(`invalid backend path segment: ${JSON.stringify(segment)}`)
    }
  }
  return new URL(`${BACKEND}/api/v1/${segments.map(encodeURIComponent).join('/')}${search}`)
}
