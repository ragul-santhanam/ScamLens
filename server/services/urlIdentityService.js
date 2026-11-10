const http = require('http');
const https = require('https');
const { analyzeUrl, getRegistrableDomain } = require('../../shared/urlAnalyzer');
const { calculateScore } = require('../../shared/scoring');
const { validateExternalUrl } = require('../utils/ssrfGuard');

/**
 * Perform a single HTTP/HTTPS HEAD request with SSRF check and TLS certificate inspection
 */
function probeSingleHop(targetUrl, timeoutMs = 1500) {
  return new Promise((resolve, reject) => {
    const isHttps = targetUrl.protocol === 'https:';
    const lib = isHttps ? https : http;

    const req = lib.request(
      targetUrl,
      {
        method: 'HEAD',
        timeout: timeoutMs,
        rejectUnauthorized: false, // Allow inspecting self-signed/invalid certs without throwing
        headers: {
          'User-Agent': 'ScamLens-IdentityChecker/1.0'
        }
      },
      (res) => {
        let certInfo = null;
        if (isHttps && res.socket && typeof res.socket.getPeerCertificate === 'function') {
          try {
            const cert = res.socket.getPeerCertificate();
            const authorized = Boolean(res.socket.authorized);
            if (cert && Object.keys(cert).length > 0) {
              certInfo = {
                authorized,
                subjectCN: (cert.subject && cert.subject.CN) || null,
                issuerO: (cert.issuer && (cert.issuer.O || cert.issuer.CN)) || null,
                validFrom: cert.valid_from || null,
                validTo: cert.valid_to || null
              };
            }
          } catch (e) {
            // Ignore cert read errors
          }
        }
        res.resume();
        resolve({
          statusCode: res.statusCode,
          location: res.headers.location || null,
          certInfo
        });
      }
    );

    req.on('timeout', () => {
      req.destroy(new Error('Connection timed out'));
    });
    req.on('error', (err) => {
      reject(err);
    });
    req.end();
  });
}

/**
 * Trace redirects safely (max 4 hops) with SSRF protection on every hop
 */
async function inspectRedirectsAndTls(rawUrl) {
  const result = {
    checked: false,
    reachable: false,
    hopCount: 0,
    chain: [],
    finalDomain: null,
    crossDomainRedirect: false,
    suspiciousRedirect: false,
    tlsCertificate: null,
    note: ''
  };

  const firstGuard = await validateExternalUrl(rawUrl);
  if (!firstGuard.safe || !firstGuard.parsedUrl) {
    result.note = firstGuard.reason || 'Live network probe skipped by SSRF protection.';
    return result;
  }

  let currentUrl = firstGuard.parsedUrl;
  const initialRegDomain = getRegistrableDomain(currentUrl.hostname);
  result.chain.push(currentUrl.href);

  const maxHops = 4;
  for (let hop = 0; hop < maxHops; hop++) {
    try {
      const hopRes = await probeSingleHop(currentUrl, 1400);
      result.checked = true;
      result.reachable = true;
      if (hopRes.certInfo && !result.tlsCertificate) {
        result.tlsCertificate = hopRes.certInfo;
      }

      if (
        hopRes.statusCode >= 300 &&
        hopRes.statusCode < 400 &&
        hopRes.location
      ) {
        const nextUrlStr = new URL(hopRes.location, currentUrl.href).href;
        const nextGuard = await validateExternalUrl(nextUrlStr);
        if (!nextGuard.safe || !nextGuard.parsedUrl) {
          result.suspiciousRedirect = true;
          result.note = 'Redirect blocked: target points to a restricted or internal network address.';
          break;
        }
        currentUrl = nextGuard.parsedUrl;
        result.hopCount++;
        result.chain.push(currentUrl.href);
      } else {
        break;
      }
    } catch (err) {
      result.note = 'Host did not respond to live connection probe within timeout.';
      break;
    }
  }

  const finalRegDomain = getRegistrableDomain(currentUrl.hostname);
  result.finalDomain = currentUrl.hostname;
  if (result.hopCount > 0 && finalRegDomain !== initialRegDomain) {
    result.crossDomainRedirect = true;
    if (result.hopCount >= 2) {
      result.suspiciousRedirect = true;
    }
  }

  return result;
}

/**
 * Query public RDAP for domain registration age (1.4s timeout)
 */
async function lookupDomainRdap(registrableDomain) {
  const intel = {
    checked: false,
    ageDays: null,
    createdDate: null,
    registrar: null,
    summary: 'Domain age intelligence unavailable for this domain/network.'
  };

  if (!registrableDomain || /^\d+\.\d+\.\d+\.\d+$/.test(registrableDomain)) {
    return intel;
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 1400);
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(registrableDomain)}`, {
      method: 'GET',
      headers: { 'Accept': 'application/rdap+json, application/json' },
      signal: controller.signal
    });
    clearTimeout(timer);

    if (!res.ok) {
      return intel;
    }

    const data = await res.json();
    const events = Array.isArray(data.events) ? data.events : [];
    const regEvent = events.find(e => e.eventAction === 'registration' && e.eventDate);

    if (regEvent && regEvent.eventDate) {
      const created = new Date(regEvent.eventDate);
      if (!isNaN(created.getTime())) {
        const ageDays = Math.max(0, Math.floor((Date.now() - created.getTime()) / (1000 * 60 * 60 * 24)));
        intel.checked = true;
        intel.ageDays = ageDays;
        intel.createdDate = created.toISOString().split('T')[0];
        intel.summary = `Domain registered on ${intel.createdDate} (~${ageDays} days old).`;
      }
    }
  } catch (e) {
    // Graceful fallback when offline or RDAP does not support the TLD
  }

  return intel;
}

/**
 * Full URL Analysis with Website Identity, Brand Impersonation, SSRF-safe Redirects & Domain Age
 */
async function analyzeUrlWithIdentity(rawUrl, options = {}) {
  const baseResult = analyzeUrl(rawUrl);
  if (baseResult.error || !baseResult.identityReport || !baseResult.normalizedDomain) {
    return baseResult;
  }

  const identityReport = baseResult.identityReport;
  const extraRules = [];

  if (options.performLiveChecks !== false) {
    const [redirectInfo, rdapInfo] = await Promise.all([
      inspectRedirectsAndTls(rawUrl),
      lookupDomainRdap(identityReport.registrableDomain)
    ]);

    identityReport.redirects = {
      checked: redirectInfo.checked,
      reachable: redirectInfo.reachable,
      hopCount: redirectInfo.hopCount,
      chain: redirectInfo.chain,
      finalDomain: redirectInfo.finalDomain,
      crossDomainRedirect: redirectInfo.crossDomainRedirect,
      suspiciousRedirect: redirectInfo.suspiciousRedirect,
      note: redirectInfo.note
    };

    if (redirectInfo.tlsCertificate) {
      identityReport.httpsInfo.certificate = redirectInfo.tlsCertificate;
      if (redirectInfo.tlsCertificate.issuerO) {
        identityReport.httpsInfo.summary = `HTTPS active (Certificate issued by ${redirectInfo.tlsCertificate.issuerO}). Note: HTTPS does NOT guarantee a website is legitimate.`;
      }
      if (redirectInfo.tlsCertificate.authorized === false && !identityReport.isVerifiedOfficial) {
        extraRules.push({
          id: 'URL_UNTRUSTED_TLS_CERT',
          title: 'Untrusted or Self-Signed HTTPS Certificate',
          weight: 25,
          explanation: 'The server presented an HTTPS certificate that could not be verified against trusted certificate authorities.'
        });
      }
    }

    if (redirectInfo.crossDomainRedirect && !identityReport.isVerifiedOfficial) {
      extraRules.push({
        id: 'URL_CROSS_DOMAIN_REDIRECT',
        title: `Redirects to Another Domain (${redirectInfo.finalDomain})`,
        weight: 20,
        explanation: `Opening this link redirects traffic from "${identityReport.normalizedDomain}" to "${redirectInfo.finalDomain}".`
      });
      identityReport.identityIndicators.push(`Cross-domain redirect detected -> ${redirectInfo.finalDomain}`);
    }

    if (rdapInfo.checked) {
      identityReport.domainIntel = rdapInfo;
      identityReport.identityIndicators.push(rdapInfo.summary);
      if (rdapInfo.ageDays !== null && rdapInfo.ageDays < 30 && !identityReport.isVerifiedOfficial) {
        extraRules.push({
          id: 'URL_NEWLY_REGISTERED_DOMAIN',
          title: `Newly Registered Domain (${rdapInfo.ageDays} days old)`,
          weight: 20,
          explanation: 'This domain was registeredless than 30 days ago. Newly registered domains warrant extra caution, though age alone does not prove malice.'
        });
      }
    }
  }

  if (extraRules.length > 0) {
    // Re-score with combined rules
    const existingWithWeights = (baseResult.firedRules || []).map(r => ({
      id: r.id,
      title: r.title,
      explanation: r.explanation,
      weight: r.severity === 'high' ? 30 : (r.severity === 'medium' ? 20 : 15)
    }));
    const combined = existingWithWeights.concat(extraRules);
    const rescored = calculateScore(combined);
    baseResult.score = Math.max(baseResult.score, rescored.score);
    baseResult.riskLevel = rescored.riskLevel;
    baseResult.riskCategory = rescored.riskCategory;
    baseResult.riskNote = rescored.riskNote;
    baseResult.riskColor = rescored.riskColor;
    baseResult.firedRules = rescored.firedRules;
    baseResult.actions = rescored.actions;
  }

  baseResult.identityReport = identityReport;
  return baseResult;
}

module.exports = {
  analyzeUrlWithIdentity,
  inspectRedirectsAndTls,
  lookupDomainRdap
};

