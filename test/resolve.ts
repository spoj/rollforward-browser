// The service's names for its tests: the portal's, *.localhost, are at this machine's address on its network, an intranet's as far as
// the proxy knows, rather than loopback, which no site reaches.
import dns from 'node:dns'
import os from 'node:os'

const here = Object.values(os.networkInterfaces()).flat().find(a => a!.family === 'IPv4' && !a!.internal)!.address
const lookup = dns.lookup
dns.lookup = ((host: string, opts: dns.LookupOptions, cb: (...a: any[]) => void) =>
  host.endsWith('.localhost') ? cb(null, [{ address: here, family: 4 }]) : lookup(host, opts, cb)) as typeof dns.lookup
