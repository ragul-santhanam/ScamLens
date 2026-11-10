const dns = require('dns').promises;
const net = require('net');

/**
 * Check if an IPv4 or IPv6 address is private, loopback, link-local, or reserved
 */
function isPrivateOrReservedIp(ip) {
  if (!ip || typeof ip !== 'string') return true;
  const trimmed = ip.trim().toLowerCase();

  // IPv6 loopback, unspecified, link-local, unique-local, IPv4-mapped
  if (net.isIPv6(trimmed)) {
    if (
      trimmed === '::1' ||
      trimmed === '::' ||
      trimmed.startsWith('fe80:') ||
      trimmed.startsWith('fc') ||
      trimmed.startsWith('fd')
    ) {
      return true;
    }
    if (trimmed.startsWith('::ffff:')) {
      const mappedIpv4 = trimmed.slice(7);
      return isPrivateOrReservedIp(mappedIpv4);
    }
    return false;
  }

  if (!net.isIPv4(trimmed)) return true;

  const parts = trimmed.split('.').map(Number);
  if (parts.length !== 4 || parts.some(n => isNaN(n) || n < 0 || n > 255)) {
    return true;
  }

  const [a, b] = parts;
  if (a === 0) return true;                             // 0.0.0.0/8
  if (a === 10) return true;                            // 10.0.0.0/8
  if (a === 127) return true;                           // 127.0.0.0/8 loopback
  if (a === 169 && b === 254) return true;              // 169.254.0.0/16 link-local / cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true;     // 172.16.0.0/12 private
  if (a === 192 && b === 168) return true;              // 192.168.0.0/16 private
  if (a === 100 && b >= 64 && b <= 127) return true;    // 100.64.0.0/10 CGNAT
  if (a >= 224) return true;                            // Multicast & reserved

  return false;
}

/**
 * Validate a URL for safe external inspection (prevents SSRF against internal/local addresses)
 * @param {string} rawUrl
 * @returns {Promise<{ safe: boolean, parsedUrl?: URL, resolvedIp?: string, reason?: string }>}
 */
async function validateExternalUrl(rawUrl) {
  try {
    const str = String(rawUrl || '').trim();
    const withProto = /^https?:\/\//i.test(str) ? str : `http://${str}`;
    const parsed = new URL(withProto);

    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return { safe: false, reason: 'Only HTTP and HTTPS protocols are permitted.' };
    }

    const hostname = parsed.hostname.toLowerCase();
    if (
      !hostname ||
      hostname === 'localhost' ||
      hostname.endsWith('.local') ||
      hostname.endsWith('.internal') ||
      hostname.endsWith('.localhost')
    ) {
      return { safe: false, reason: 'Local or internal hostnames are blocked by SSRF protection.' };
    }

    // Direct IP check
    if (net.isIP(hostname)) {
      if (isPrivateOrReservedIp(hostname)) {
        return { safe: false, reason: 'Private or loopback IP addresses are blocked by SSRF protection.' };
      }
      return { safe: true, parsedUrl: parsed, resolvedIp: hostname };
    }

    // Resolve DNS with 1.5s timeout
    const lookupPromise = dns.lookup(hostname, { all: true });
    const timeoutPromise = new Promise((_, reject) =>
      setTimeout(() => reject(new Error('DNS lookup timeout')), 1500)
    );

    const addresses = await Promise.race([lookupPromise, timeoutPromise]);
    if (!Array.isArray(addresses) || addresses.length === 0) {
      return { safe: false, reason: 'Domain name could not be resolved in DNS.' };
    }

    for (const addr of addresses) {
      if (isPrivateOrReservedIp(addr.address)) {
        return { safe: false, reason: 'Domain resolves to a private or reserved network IP address.' };
      }
    }

    return { safe: true, parsedUrl: parsed, resolvedIp: addresses[0].address };
  } catch (err) {
    return { safe: false, reason: err.message || 'Unable to verify external host safety.' };
  }
}

module.exports = {
  isPrivateOrReservedIp,
  validateExternalUrl
};

