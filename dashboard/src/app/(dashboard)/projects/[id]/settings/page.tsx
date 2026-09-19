import { notFound } from 'next/navigation'
import { cookies } from 'next/headers'
import { ProjectPolicySection } from '@/components/project-policy-section'
import { backendUrl } from '@/lib/backend'
import type { CustomPolicy } from '@/components/policy-editor'

async function backendFetch<T>(path: string): Promise<T | null> {
  const cookieStore = await cookies()
  const token = cookieStore.get('valt_access_token')?.value
  if (!token) return null
  let url: URL
  try {
    url = backendUrl(path)
  } catch {
    return null
  }
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${token}` },
    cache: 'no-store',
  })
  if (!res.ok) return null
  return res.json() as Promise<T>
}

export default async function ProjectSettingsPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params
  const policy = await backendFetch<CustomPolicy>(`/projects/${id}/policy`)
  if (policy === null) notFound()

  return (
    <div className="max-w-lg space-y-4">
      <h2 className="text-lg font-semibold">Project Settings</h2>
      <p className="text-sm text-muted-foreground">
        Policy settings here apply as defaults for all secrets in this project.
        Per-secret policies can override these values.
      </p>
      <ProjectPolicySection projectId={id} initialPolicy={policy ?? {}} />
    </div>
  )
}
