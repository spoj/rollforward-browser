export type Page<T> = {
  oldestCursor: number
  nextCursor: number
  hasMore: boolean
  dropped: number
  entries: T[]
}

export function page<T, U = T>(
  items: readonly T[],
  cursorOf: (item: T) => number,
  currentCursor: number,
  after: number,
  limit: number,
  maxBytes: number,
  dropped: number,
  map?: (item: T) => U,
): Page<U> {
  const oldestCursor = items.length ? cursorOf(items[0]) : currentCursor
  const entries: U[] = []
  let bytes = 128
  let lastIdx = -1
  for (let i = 0; i < items.length; i++) {
    const item = items[i]
    if (cursorOf(item) <= after) continue
    const out = map ? map(item) : (item as unknown as U)
    const size = Buffer.byteLength(JSON.stringify(out), 'utf8') + 1
    if (entries.length > 0 && (entries.length >= limit || bytes + size > maxBytes)) break
    entries.push(out)
    bytes += size
    lastIdx = i
  }
  const hasMore = lastIdx >= 0 && lastIdx < items.length - 1
  const nextCursor = lastIdx >= 0 ? cursorOf(items[lastIdx]) : Math.max(after, oldestCursor)
  return { oldestCursor, nextCursor, hasMore, dropped, entries }
}
