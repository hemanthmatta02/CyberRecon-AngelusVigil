import { useEffect, useState } from 'react'

// sessionStorage is intentionally used for UI/session state: every browser tab
// gets an isolated history and selections, and refreshes preserve that tab.
function storage(): Storage {
  return window.sessionStorage
}

export function readStored<T>(key: string, fallback: T): T {
  try {
    const raw = storage().getItem(key)
    return raw ? (JSON.parse(raw) as T) : fallback
  } catch {
    return fallback
  }
}

export function writeStored<T>(key: string, value: T): void {
  try { storage().setItem(key, JSON.stringify(value)) } catch { /* storage may be unavailable */ }
}

export function removeStored(key: string): void {
  try { storage().removeItem(key) } catch { /* storage may be unavailable */ }
}

export function usePersistentState<T>(key: string, fallback: T) {
  const [value, setValue] = useState<T>(() => readStored(key, fallback))
  useEffect(() => { writeStored(key, value) }, [key, value])
  return [value, setValue] as const
}
