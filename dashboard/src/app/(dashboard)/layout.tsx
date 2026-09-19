import { redirect } from 'next/navigation'
import { headers, cookies } from 'next/headers'
import { getSession } from '@/lib/auth'
import { backendUrl } from '@/lib/backend'
import Sidebar from '@/components/layout/sidebar'
import Header from '@/components/layout/header'

// Check if the user has any organizations. Used to detect first-time users
// whose auto-created org may have failed, so we redirect them to onboarding.
async function userHasOrg(token: string): Promise<boolean> {
  try {
    const res = await fetch(backendUrl('/orgs'), {
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      // Short timeout via signal — don't block layout for too long.
      signal: AbortSignal.timeout(3000),
    })
    if (!res.ok) return true // Fail open: don't redirect if backend unreachable.
    const data = await res.json() as { orgs?: unknown[] } | unknown[]
    const orgs = Array.isArray(data) ? data : ((data as { orgs?: unknown[] }).orgs ?? [])
    return orgs.length > 0
  } catch {
    return true // Fail open.
  }
}

export default async function DashboardLayout({ children }: { children: React.ReactNode }) {
  const session = await getSession()
  if (!session) redirect('/login')

  const headersList = await headers()
  const pathname = headersList.get('x-pathname') ?? ''

  // Only run onboarding check on the root dashboard path to avoid overhead on every page.
  // The onboarding page itself is outside this layout group so it won't trigger this.
  if (pathname === '/' || pathname === '') {
    const cookieStore = await cookies()
    const token = cookieStore.get('valt_access_token')?.value
    if (token) {
      const hasOrg = await userHasOrg(token)
      if (!hasOrg) redirect('/onboarding')
    }
  }

  return (
    <div className="flex h-screen bg-background">
      <Sidebar />
      <div className="flex flex-col flex-1 overflow-hidden">
        <Header pathname={pathname} />
        <main className="flex-1 overflow-y-auto p-6">
          {children}
        </main>
      </div>
    </div>
  )
}
