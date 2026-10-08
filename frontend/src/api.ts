export async function request(path: string, body?: unknown, token = ''): Promise<any> {
  const response = await fetch('/api' + path, body === undefined ? {} : { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, body: JSON.stringify(body) })
  if (!response.ok) { const detail = await response.json().catch(() => ({})); throw new Error(typeof detail.detail === 'string' ? detail.detail : `Request failed (${response.status})`) }
  return response.json()
}
export const percentage = (value?: number) => value == null ? 'Not evaluated' : `${(value * 100).toFixed(1)}%`
export const timestamp = (value?: number) => value ? new Date(value * 1000).toLocaleString() : '—'
