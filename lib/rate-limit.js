const attempts = globalThis.__secureCodeAttempts || new Map();
globalThis.__secureCodeAttempts = attempts;
export function allowRequest(key, max = 8, windowMs = 10 * 60 * 1000) {
  const now = Date.now();
  const current = attempts.get(key);
  if (!current || current.reset < now) {
    attempts.set(key, { count: 1, reset: now + windowMs });
    return true;
  }
  current.count += 1;
  return current.count <= max;
}

