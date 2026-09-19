import { notFound } from 'next/navigation'
import { cookies } from 'next/headers'
import { formatDate } from '@/lib/utils'
import { backendUrl } from '@/lib/backend'
import type { Secret, SecretPolicyBinding } from '@/types/api'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { SecretPolicySection } from '@/components/secret-policy-section'
import type { CustomPolicy } from '@/components/policy-editor'
import { POLICY_LABELS } from '@/components/policies/policy-helpers'

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

async function getPolicyBinding(id: string): Promise<SecretPolicyBinding | null> {
  const cookieStore = await cookies()
  const token = cookieStore.get('valt_access_token')?.value
  if (!token) return null
  let url: URL
  try {
    url = backendUrl(`/secrets/${id}/policy-binding`)
  } catch {
    return null
  }
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${token}` },
    cache: 'no-store',
  })
  if (!res.ok) return null
  return res.json() as Promise<SecretPolicyBinding>
}

export default async function SecretDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params
  const [secret, policy, binding] = await Promise.all([
    backendFetch<Secret>(`/secrets/${id}`),
    backendFetch<CustomPolicy>(`/secrets/${id}/policy`),
    getPolicyBinding(id),
  ])
  if (!secret) notFound()

  return (
    <div className="max-w-2xl space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">{secret.name}</h2>
        <Badge variant={secret.status === 'active' ? 'default' : 'outline'}>{secret.status}</Badge>
      </div>
      <Card>
        <CardHeader><CardTitle className="text-base">Details</CardTitle></CardHeader>
        <CardContent className="space-y-3 text-sm">
          {secret.description && (
            <div><span className="text-muted-foreground">Description: </span>{secret.description}</div>
          )}
          <div><span className="text-muted-foreground">Type: </span>
            <Badge variant="secondary">{secret.credential_type}</Badge>
          </div>
          {secret.source && (
            <div><span className="text-muted-foreground">Source: </span>{secret.source}</div>
          )}
          <div><span className="text-muted-foreground">Created: </span>{formatDate(secret.created_at)}</div>
          <div><span className="text-muted-foreground">Updated: </span>{formatDate(secret.updated_at)}</div>
        </CardContent>
      </Card>
      <SecretPolicySection secretId={id} initialPolicy={policy ?? {}} />
      {binding && (
        <Card>
          <CardHeader><CardTitle className="text-base">Policy binding</CardTitle></CardHeader>
          <CardContent className="space-y-2 text-sm">
            {binding.template ? (
              <div className="flex items-center gap-2">
                <span className="text-muted-foreground">Template:</span>
                <Badge variant="secondary">{binding.template.name}</Badge>
                <Badge variant="outline">v{binding.template_version}</Badge>
              </div>
            ) : (
              <p className="text-muted-foreground">No template bound.</p>
            )}
            {binding.override_warnings.length > 0 && (
              <div className="space-y-1">
                <p className="text-amber-700 dark:text-amber-300">Weaker override warnings</p>
                <div className="flex flex-wrap gap-1">
                  {binding.override_warnings.map((w) => (
                    <Badge key={w} variant="outline" className="border-amber-300 text-amber-700 dark:text-amber-300">
                      {POLICY_LABELS[w.replace('weaker:', '') as keyof typeof POLICY_LABELS] ?? w}
                    </Badge>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  )
}
