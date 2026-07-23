/**
 * Tiny LRU map for bounded in-process caches (e.g. session principals).
 *
 * `get` / `set` refresh recency by re-inserting into a `Map` (insertion order).
 * When size exceeds `max`, the oldest key is evicted.
 */

/**
 * Least-recently-used string-keyed map; oldest entries evicted past `max`.
 */
export class LruMap<V> {
  private readonly map = new Map<string, V>();

  constructor(private readonly max: number) {}

  get size(): number {
    return this.map.size;
  }

  get(key: string): V | undefined {
    const value = this.map.get(key);
    if (value === undefined) return undefined;
    // Refresh recency: delete + re-set moves the key to the end.
    this.map.delete(key);
    this.map.set(key, value);
    return value;
  }

  set(key: string, value: V): void {
    if (this.map.has(key)) this.map.delete(key);
    this.map.set(key, value);
    while (this.map.size > this.max) {
      const oldest = this.map.keys().next().value;
      if (oldest === undefined) break;
      this.map.delete(oldest);
    }
  }

  delete(key: string): boolean {
    return this.map.delete(key);
  }

  clear(): void {
    this.map.clear();
  }
}
