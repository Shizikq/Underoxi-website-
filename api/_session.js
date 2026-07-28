/**
 * Signed cookie sessions for Vercel serverless.
 * No in-memory store — works across all function instances.
 */
const crypto = require('crypto');

const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

function getSecret() {
  // Prefer dedicated secret; fall back to password hash so no extra env is required
  return process.env.SESSION_SECRET || process.env.OWNER_PASSWORD_HASH || 'underoxi-fallback-secret';
}

function sign(payload) {
  return crypto.createHmac('sha256', getSecret()).update(payload).digest('hex');
}

/**
 * Create a signed session token (stored in HttpOnly cookie).
 */
function createSession() {
  const expiresAt = Date.now() + SESSION_TTL_MS;
  const payload = 'owner.' + expiresAt;
  const sig = sign(payload);
  const token = payload + '.' + sig;
  return {
    id: token,
    createdAt: Date.now(),
    expiresAt: expiresAt,
    data: { authenticated: true, role: 'owner' }
  };
}

/**
 * Validate signed session token from cookie.
 */
function getSession(sessionId) {
  if (!sessionId || typeof sessionId !== 'string') return null;

  const parts = sessionId.split('.');
  // owner.<expiresAt>.<signature>
  if (parts.length !== 3) return null;

  const role = parts[0];
  const expiresAt = parseInt(parts[1], 10);
  const sig = parts[2];

  if (role !== 'owner' || !expiresAt || !sig) return null;
  if (Date.now() > expiresAt) return null;

  const payload = role + '.' + expiresAt;
  const expected = sign(payload);

  // timing-safe compare
  try {
    const a = Buffer.from(sig, 'hex');
    const b = Buffer.from(expected, 'hex');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  } catch (e) {
    return null;
  }

  return {
    id: sessionId,
    expiresAt: expiresAt,
    data: { authenticated: true, role: 'owner' }
  };
}

/**
 * No server-side store — logout only clears the cookie on the client.
 */
function destroySession() {
  // intentional no-op
}

module.exports = { createSession, getSession, destroySession };
