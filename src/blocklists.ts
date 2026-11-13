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
    for (const [i, list] of lists.entries()) {
      const domains = list.split('\n').map(line => line.split('#')[0].trim().toLowerCase().replace(/\.$/, '')).filter(Boolean)
      // An empty file, or a page of HTML where a list was, as from a captive portal or an outage, is a failed fetch.
      if (!domains.length || !domains.every(d => /^[a-z0-9_-]+(\.[a-z0-9_-]+)*$/.test(d))) throw new Error(`${urls[i]}: not a list of domains`)
      for (const domain of domains) next.add(domain)
    }
    if (blocklist && next.size < blocklist.size / 2) throw new Error(`${next.size} domains, fewer than half the ${blocklist.size} in use`)
    blocklist = next
  } catch (e) {
    console.error('loading blocklists:', e)
    // With none yet, open sessions are refused: try again in a minute, not a day.
    if (!blocklist) setTimeout(loadBlocklists, 60_000).unref()
  }
}

export const isBlocked = (host: string) => {
  const parts = host.toLowerCase().replace(/\.$/, '').split('.')
  return parts.some((_, i) => blocklist!.has(parts.slice(i).join('.')))
}
