// The service's names for its tests: the portal's, *.localhost, are at this machine's address on its network, an intranet's as far as
// the proxy knows, rather than loopback, which no site reaches.
import dns from 'node:dns'
import os from 'node:os'
import https from 'node:https'

const here = Object.values(os.networkInterfaces()).flat().find(a => a!.family === 'IPv4' && !a!.internal)!.address
const lookup = dns.lookup
dns.lookup = ((host: string, opts: dns.LookupOptions, cb: (...a: any[]) => void) =>
  host === 'public.example' ? cb(null, [{ address: '93.184.215.14', family: 4 }])
    : host.endsWith('.localhost') ? cb(null, [{ address: here, family: 4 }]) : lookup(host, opts, cb)) as typeof dns.lookup

// The proxy checks a public answer for public.example; only the test's transport then connects it to the local portal.
const request = https.request
https.request = ((url: URL, opts: https.RequestOptions, cb: any) => {
  if (url.hostname !== 'public.example') return request(url, opts, cb)
  return request(url, { ...opts, lookup: (host, options, done) => opts.lookup!(host, options, (err: Error | null) => done(err, here, 4)) }, cb)
}) as typeof https.request
