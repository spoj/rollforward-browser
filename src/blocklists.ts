export let blocklist: Set<string> | undefined

export async function loadBlocklists() {
  try {
    const urls = (process.env.BROWSER_BLOCKLISTS ?? 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.medium-onlydomains.txt').split(/\s+/).filter(Boolean)
    const lists = await Promise.all(urls.map(async url => {
      const res = await fetch(url, { signal: AbortSignal.timeout(60_000) })
      if (!res.ok) throw new Error(`${url}: ${res.status}`)
      return await res.text()
    }))
    const next = new Set<string>()
    for (const list of lists) for (const line of list.split('\n')) {
      const domain = line.split('#')[0].trim().toLowerCase().replace(/\.$/, '')
      if (domain) next.add(domain)
    }
    blocklist = next
  } catch (e) {
    console.error('loading blocklists:', e)
  }
}

export const isBlocked = (host: string) => {
  const parts = host.toLowerCase().replace(/\.$/, '').split('.')
  return parts.some((_, i) => blocklist!.has(parts.slice(i).join('.')))
}
