/**
 * Minimal cookie helpers (no external deps — avoids ESM issues on Vercel).
 */

function parse(cookieHeader) {
  const out = {};
  if (!cookieHeader || typeof cookieHeader !== 'string') return out;
  cookieHeader.split(';').forEach(function (part) {
    const idx = part.indexOf('=');
    if (idx === -1) return;
    const key = part.slice(0, idx).trim();
    const val = part.slice(idx + 1).trim();
    if (key) {
      try {
        out[key] = decodeURIComponent(val);
      } catch (e) {
        out[key] = val;
      }
    }
  });
  return out;
}

function serialize(name, value, options) {
  options = options || {};
  var str = name + '=' + encodeURIComponent(value == null ? '' : String(value));
  if (options.maxAge != null) {
    str += '; Max-Age=' + Math.floor(options.maxAge);
  }
  if (options.path) str += '; Path=' + options.path;
  if (options.domain) str += '; Domain=' + options.domain;
  if (options.expires) str += '; Expires=' + options.expires.toUTCString();
  if (options.httpOnly) str += '; HttpOnly';
  if (options.secure) str += '; Secure';
  if (options.sameSite) str += '; SameSite=' + options.sameSite;
  return str;
}

module.exports = { parse: parse, serialize: serialize };
