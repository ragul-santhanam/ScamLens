/**
 * ScamLens URL Analysis & Website Identity Engine
 * Evaluates URLs against phishing patterns, obfuscation techniques,
 * domain similarity, lookalike/typosquatting, character substitution,
 * homograph/punycode spoofing, brand impersonation, and transport security.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory(require('./config'), require('./scoring'), require('./masking'));
  } else {
    root.ScamLensUrlAnalyzer = factory(root.ScamLensConfig, root.ScamLensScoring, root.ScamLensMasking);
  }
}(typeof self !== 'undefined' ? self : this, function (config, scoring, masking) {
  'use strict';

  var cfg = config || (typeof window !== 'undefined' ? window.ScamLensConfig : {});
  var sc = scoring || (typeof window !== 'undefined' ? window.ScamLensScoring : {});
  var mask = masking || (typeof window !== 'undefined' ? window.ScamLensMasking : {});

  // Suspicious Top Level Domains commonly abused by disposable phishing campaigns
  var SUSPICIOUS_TLDS = [
    'xyz', 'top', 'click', 'work', 'loan', 'buzz', 'club', 'gq', 'cf',
    'ml', 'tk', 'fit', 'rest', 'guru', 'icu', 'racing', 'online', 'site',
    'live', 'shop', 'vip', 'win', 'bid', 'stream', 'download', 'xin', ' mom'
  ];

  // Common URL Shorteners that hide true destinations
  var KNOWN_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'buff.ly', 'ow.ly',
    'cutt.ly', 'rb.gy', 'shorturl.at', 'tiny.cc', 'v.ht', 'rebrand.ly'
  ];

  // Authoritative Brand Registry: brand key -> { displayName, officialDomains }
  var BRAND_REGISTRY = {
    'sbi': { displayName: 'State Bank of India (SBI)', domains: ['sbi.co.in', 'onlinesbi.sbi', 'statebankofindia.com', 'onlinesbi.com', 'sbicard.com'] },
    'hdfc': { displayName: 'HDFC Bank', domains: ['hdfcbank.com', 'hdfc.com', 'hdfcbank.co.in'] },
    'icici': { displayName: 'ICICI Bank', domains: ['icicibank.com', 'icici.com', 'icicidirect.com'] },
    'axis': { displayName: 'Axis Bank', domains: ['axisbank.com', 'axisbank.co.in'] },
    'kotak': { displayName: 'Kotak Mahindra Bank', domains: ['kotak.com', 'kotakbank.com'] },
    'pnb': { displayName: 'Punjab National Bank (PNB)', domains: ['pnbindia.in', 'netpnb.com'] },
    'canara': { displayName: 'Canara Bank', domains: ['canarabank.com', 'canarabank.in'] },
    'bankofbaroda': { displayName: 'Bank of Baroda', domains: ['bankofbaroda.in', 'bobibanking.com'] },
    'unionbank': { displayName: 'Union Bank of India', domains: ['unionbankofindia.co.in'] },
    'indusind': { displayName: 'IndusInd Bank', domains: ['indusind.com'] },
    'yesbank': { displayName: 'Yes Bank', domains: ['yesbank.in'] },
    'paytm': { displayName: 'Paytm', domains: ['paytm.com', 'paytmbank.com'] },
    'phonepe': { displayName: 'PhonePe', domains: ['phonepe.com'] },
    'googlepay': { displayName: 'Google Pay', domains: ['pay.google.com', 'google.com', 'google.co.in'] },
    'gpay': { displayName: 'Google Pay (GPay)', domains: ['pay.google.com', 'google.com'] },
    'bhim': { displayName: 'BHIM UPI / NPCI', domains: ['bhimupi.org.in', 'npci.org.in'] },
    'npci': { displayName: 'NPCI', domains: ['npci.org.in', 'bhimupi.org.in'] },
    'razorpay': { displayName: 'Razorpay', domains: ['razorpay.com'] },
    'amazon': { displayName: 'Amazon', domains: ['amazon.com', 'amazon.in', 'amzn.in', 'amzn.to'] },
    'flipkart': { displayName: 'Flipkart', domains: ['flipkart.com'] },
    'meesho': { displayName: 'Meesho', domains: ['meesho.com'] },
    'myntra': { displayName: 'Myntra', domains: ['myntra.com'] },
    'indiapost': { displayName: 'India Post', domains: ['indiapost.gov.in'] },
    'irctc': { displayName: 'IRCTC', domains: ['irctc.co.in', 'irctc.com'] },
    'uidai': { displayName: 'UIDAI (Aadhaar)', domains: ['uidai.gov.in', 'myaadhaar.uidai.gov.in'] },
    'incometax': { displayName: 'Income Tax Department', domains: ['incometax.gov.in', 'incometaxindia.gov.in'] },
    'parivahan': { displayName: 'Parivahan Sewa', domains: ['parivahan.gov.in', 'echallan.parivahan.gov.in'] },
    'cybercrime': { displayName: 'National Cyber Crime Reporting Portal', domains: ['cybercrime.gov.in'] },
    'epfo': { displayName: 'EPFO India', domains: ['epfindia.gov.in'] },
    'lic': { displayName: 'LIC of India', domains: ['licindia.in'] },
    'jio': { displayName: 'Reliance Jio', domains: ['jio.com'] },
    'airtel': { displayName: 'Airtel', domains: ['airtel.in'] },
    'bsnl': { displayName: 'BSNL', domains: ['bsnl.co.in'] },
    'google': { displayName: 'Google', domains: ['google.com', 'google.co.in', 'accounts.google.com'] },
    'apple': { displayName: 'Apple', domains: ['apple.com', 'icloud.com'] },
    'microsoft': { displayName: 'Microsoft', domains: ['microsoft.com', 'live.com', 'office.com'] },
    'netflix': { displayName: 'Netflix', domains: ['netflix.com'] },
    'paypal': { displayName: 'PayPal', domains: ['paypal.com', 'paypal.me'] },
    'whatsapp': { displayName: 'WhatsApp', domains: ['whatsapp.com', 'wa.me'] },
    'instagram': { displayName: 'Instagram', domains: ['instagram.com'] },
    'telegram': { displayName: 'Telegram', domains: ['telegram.org', 't.me'] }
  };

  // Legacy map preserved for backward compatibility
  var BRAND_OFFICIAL_DOMAINS = {};
  Object.keys(BRAND_REGISTRY).forEach(function (k) {
    BRAND_OFFICIAL_DOMAINS[k] = BRAND_REGISTRY[k].domains;
  });

  // Known malicious/phishing test & disposable domains list
  var KNOWN_MALICIOUS_DOMAINS = [
    'sbi-kyc.xyz',
    'paytm-secure-login.xyz',
    'fake-bank-login.xyz',
    'hdfc-pan-update.top',
    'icici-reward-points.click',
    'indiapost-parcel-track.xyz',
    'echallan-parivahan-pay.online'
  ];

  /**
   * Check if a hostname belongs to an official domain list
   */
  function isOfficialDomain(hostname, officialList) {
    var lowerHost = (hostname || '').toLowerCase();
    for (var i = 0; i < officialList.length; i++) {
      var official = officialList[i];
      if (lowerHost === official || lowerHost.endsWith('.' + official)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Extract registrable base domain (e.g. sub.example.co.in -> example.co.in)
   */
  function getRegistrableDomain(hostname) {
    var parts = (hostname || '').toLowerCase().split('.').filter(Boolean);
    if (parts.length <= 2) return parts.join('.');
    var twoPartTlds = ['co.in', 'gov.in', 'org.in', 'net.in', 'ac.in', 'co.uk', 'com.au'];
    var lastTwo = parts.slice(-2).join('.');
    if (twoPartTlds.indexOf(lastTwo) !== -1 && parts.length >= 3) {
      return parts.slice(-3).join('.');
    }
    return parts.slice(-2).join('.');
  }

  /**
   * Compute Levenshtein edit distance between two strings
   */
  function levenshtein(a, b) {
    if (a === b) return 0;
    if (!a.length) return b.length;
    if (!b.length) return a.length;

    var matrix = [];
    var i, j;
    for (i = 0; i <= b.length; i++) {
      matrix[i] = [i];
    }
    for (j = 0; j <= a.length; j++) {
      matrix[0][j] = j;
    }
    for (i = 1; i <= b.length; i++) {
      for (j = 1; j <= a.length; j++) {
        if (b.charAt(i - 1) === a.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1, // substitution
            matrix[i][j - 1] + 1,     // insertion
            matrix[i - 1][j] + 1      // deletion
          );
        }
      }
    }
    return matrix[b.length][a.length];
  }

  /**
   * Normalize visual character substitutions (homoglyphs / leetspeak)
   * e.g., paypa1 -> paypal, g00gle -> google, arnazon -> amazon, vv -> w
   */
  function deobfuscateHomoglyphs(str) {
    return (str || '')
      .toLowerCase()
      .replace(/rn/g, 'm')
      .replace(/vv/g, 'w')
      .replace(/0/g, 'o')
      .replace(/1/g, 'l')
      .replace(/3/g, 'e')
      .replace(/4/g, 'a')
      .replace(/5/g, 's')
      .replace(/8/g, 'b')
      .replace(/@/g, 'a');
  }

  function deobfuscateWithI(str) {
    return (str || '')
      .toLowerCase()
      .replace(/1/g, 'i')
      .replace(/0/g, 'o')
      .replace(/!/g, 'i');
  }

  /**
   * Inspect domain for brand impersonation, typosquatting, and character substitutions
   */
  function inspectBrandIdentity(hostname) {
    var lowerHost = (hostname || '').toLowerCase();
    var regDomain = getRegistrableDomain(lowerHost);
    var domainLabel = regDomain.split('.')[0] || '';
    var fullLabels = lowerHost.split('.').slice(0, -1).join('.');

    var findings = {
      isVerifiedOfficial: false,
      verifiedBrand: null,
      impersonatedBrand: null,
      officialDomains: [],
      matchType: null, // 'exact_brand_in_unofficial_domain' | 'char_substitution' | 'typosquatting_lookalike'
      explanation: null,
      similarityPercent: 0,
      substitutionsDetected: []
    };

    var brandKeys = Object.keys(BRAND_REGISTRY);

    // 1. Check if hostname is an authoritative official domain
    for (var i = 0; i < brandKeys.length; i++) {
      var bKey = brandKeys[i];
      var bInfo = BRAND_REGISTRY[bKey];
      if (isOfficialDomain(lowerHost, bInfo.domains)) {
        findings.isVerifiedOfficial = true;
        findings.verifiedBrand = bInfo.displayName;
        findings.officialDomains = bInfo.domains;
        findings.explanation = 'Matches known official domain (' + regDomain + ') for ' + bInfo.displayName + '.';
        return findings;
      }
    }

    // 2. Check exact brand keyword inside an unauthorized domain
    for (var b = 0; b < brandKeys.length; b++) {
      var brand = brandKeys[b];
      if (brand.length >= 3 && lowerHost.indexOf(brand) !== -1) {
        var entry = BRAND_REGISTRY[brand];
        findings.impersonatedBrand = entry.displayName;
        findings.officialDomains = entry.domains;
        findings.matchType = 'exact_brand_in_unofficial_domain';
        findings.similarityPercent = 90;
        findings.explanation = 'The domain "' + lowerHost + '" includes the brand keyword "' + brand + '" but is not an official domain of ' + entry.displayName + ' (official: ' + entry.domains.slice(0, 2).join(', ') + ').';
        return findings;
      }
    }

    // 3. Check character substitution (0->o, 1->l, 1->i, rn->m, vv->w)
    var tokens = fullLabels.split(/[-._]+/).filter(Boolean);
    tokens.unshift(domainLabel);

    for (var t = 0; t < tokens.length; t++) {
      var tok = tokens[t];
      var deobL = deobfuscateHomoglyphs(tok);
      var deobI = deobfuscateWithI(tok);

      for (var k = 0; k < brandKeys.length; k++) {
        var targetBrand = brandKeys[k];
        if (targetBrand.length < 3) continue;
        var bEntry = BRAND_REGISTRY[targetBrand];

        if ((deobL === targetBrand || deobI === targetBrand || deobL.indexOf(targetBrand) !== -1 || deobI.indexOf(targetBrand) !== -1) && tok.indexOf(targetBrand) === -1) {
          findings.impersonatedBrand = bEntry.displayName;
          findings.officialDomains = bEntry.domains;
          findings.matchType = 'char_substitution';
          findings.similarityPercent = 88;
          findings.explanation = 'The domain token "' + tok + '" uses deceptive character substitution to visually mimic "' + targetBrand + '" (' + bEntry.displayName + '; official: ' + bEntry.domains[0] + ').';
          return findings;
        }
      }
    }

    // 4. Check typosquatting / lookalike spelling via Levenshtein distance against official domain labels and brand names
    for (var m = 0; m < brandKeys.length; m++) {
      var brKey = brandKeys[m];
      if (brKey.length < 4) continue;
      var brEntry = BRAND_REGISTRY[brKey];

      var candidateTargets = [brKey];
      brEntry.domains.forEach(function (d) {
        var firstPart = d.split('.')[0];
        if (firstPart && candidateTargets.indexOf(firstPart) === -1) {
          candidateTargets.push(firstPart);
        }
      });

      for (var c = 0; c < candidateTargets.length; c++) {
        var officialLabel = candidateTargets[c];
        if (officialLabel.length < 4) continue;

        for (var tkIdx = 0; tkIdx < tokens.length; tkIdx++) {
          var tokenToTest = tokens[tkIdx];
          if (Math.abs(tokenToTest.length - officialLabel.length) > 2) continue;
          var dist = levenshtein(tokenToTest, officialLabel);
          var maxAllowedDist = officialLabel.length >= 7 ? 2 : 1;

          if (dist > 0 && dist <= maxAllowedDist) {
            var maxLen = Math.max(tokenToTest.length, officialLabel.length);
            var sim = Math.round(((maxLen - dist) / maxLen) * 100);
            findings.impersonatedBrand = brEntry.displayName;
            findings.officialDomains = brEntry.domains;
            findings.matchType = 'typosquatting_lookalike';
            findings.similarityPercent = sim;
            findings.explanation = 'The domain segment "' + tokenToTest + '" is a close lookalike/misspelling (' + sim + '% visual similarity) of "' + officialLabel + '" (' + brEntry.displayName + '; official: ' + brEntry.domains[0] + ').';
            return findings;
          }
        }
      }
    }

    return findings;
  }

  /**
   * Analyze a URL string for security risks and website identity
   * @param {string} rawUrl - The URL to analyze
   * @returns {Object} Analysis result
   */
  function analyzeUrl(rawUrl) {
    if (!rawUrl || typeof rawUrl !== 'string') {
      var errResult = sc.calculateScore([]);
      errResult.maskedPreview = '';
      errResult.error = 'Invalid URL input';
      return errResult;
    }

    var trimmed = rawUrl.trim();
    var firedRules = [];

    // Check for @ symbol in raw string before URL parsing (URL auth trick)
    if (trimmed.indexOf('@') !== -1) {
      firedRules.push({
        id: 'URL_AT_SYMBOL',
        title: 'URL Obfuscation with "@" Symbol',
        weight: 30,
        explanation: 'The "@" character in a URL can trick browsers into routing to an unexpected deceptive domain.'
      });
    }

    var parsed = null;
    var validUrl = false;

    try {
      // Auto-prefix http if scheme missing for standard parsing
      var urlToParse = trimmed;
      if (!/^https?:\/\//i.test(urlToParse)) {
        urlToParse = 'http://' + urlToParse;
      }
      parsed = new URL(urlToParse);
      validUrl = true;
    } catch (e) {
      // Malformed URL
      firedRules.push({
        id: 'URL_MALFORMED',
        title: 'Malformed or Unparseable URL',
        weight: 25,
        explanation: 'This address is improperly formatted or uses invalid protocol structures.'
      });
    }

    var identityReport = {
      enteredUrl: trimmed,
      normalizedDomain: '',
      registrableDomain: '',
      protocol: '',
      isHttps: false,
      httpsNote: 'HTTPS only encrypts data in transit; it does NOT prove that a website is legitimate or trustworthy.',
      isVerifiedOfficial: false,
      verifiedBrand: null,
      brandSimilarity: null,
      identityIndicators: [],
      httpsInfo: {
        usesHttps: false,
        scheme: 'http',
        summary: 'Unencrypted HTTP connection'
      },
      domainIntel: {
        checked: false,
        ageDays: null,
        createdDate: null,
        registrar: null,
        summary: 'Live domain registration intelligence is evaluated when online.'
      },
      redirects: {
        checked: false,
        hopCount: 0,
        chain: [],
        suspiciousRedirect: false
      }
    };

    if (validUrl && parsed) {
      var hostname = parsed.hostname.toLowerCase();
      var fullHref = parsed.href;
      var protocol = parsed.protocol.toLowerCase();
      var pathAndSearch = (parsed.pathname + parsed.search).toLowerCase();
      var regDomain = getRegistrableDomain(hostname);

      identityReport.normalizedDomain = hostname;
      identityReport.registrableDomain = regDomain;
      identityReport.protocol = protocol.replace(':', '');
      identityReport.isHttps = protocol === 'https:';
      identityReport.httpsInfo = {
        usesHttps: protocol === 'https:',
        scheme: protocol.replace(':', ''),
        summary: protocol === 'https:'
          ? 'Uses HTTPS transport encryption (Note: phishing sites also routinely use free HTTPS certificates).'
          : 'Plain HTTP connection without transport encryption.'
      };

      // 1. IP Host (e.g., http://192.168.1.1 or http://45.33.32.156)
      var ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
      if (ipRegex.test(hostname)) {
        firedRules.push({
          id: 'URL_IP_HOST',
          title: 'Direct IP Address Instead of Domain',
          weight: 30,
          explanation: 'Legitimate services use named domains; direct IP addresses often conceal malicious servers.'
        });
        identityReport.identityIndicators.push('Uses a raw numerical IP address instead of a registered domain name.');
      }

      // 2. Punycode (IDN homograph attack e.g., xn--)
      if (hostname.indexOf('xn--') !== -1) {
        firedRules.push({
          id: 'URL_PUNYCODE',
          title: 'Punycode Internationalized Domain',
          weight: 30,
          explanation: 'Punycode (xn--) can be used in homograph attacks to visually mimic trusted domain names.'
        });
        identityReport.identityIndicators.push('Contains IDN Punycode ("xn--"), often used for visual homograph spoofing.');
      }

      // 3. More than 3 subdomains (deep subdomain nesting)
      var hostParts = hostname.split('.');
      if (hostParts.length > 4 && !ipRegex.test(hostname)) {
        firedRules.push({
          id: 'URL_DEEP_SUBDOMAINS',
          title: 'Excessive Subdomain Nesting',
          weight: 20,
          explanation: 'Multiple subdomains are frequently used to confuse users into thinking they are on a trusted portal.'
        });
        identityReport.identityIndicators.push('Excessive subdomain depth (' + (hostParts.length - 2) + ' levels).');
      }

      // 4. Suspicious TLD
      var tld = hostParts[hostParts.length - 1];
      if (SUSPICIOUS_TLDS.indexOf(tld) !== -1) {
        firedRules.push({
          id: 'URL_SUSPICIOUS_TLD',
          title: 'High-Risk Domain Extension (.' + tld + ')',
          weight: 25,
          explanation: 'The extension ".' + tld + '" is commonly associated with disposable or fraudulent websites.'
        });
        identityReport.identityIndicators.push('Uses high-risk top-level domain ".' + tld + '".');
      }

      // 5. Known shorteners (scored as Suspicious by default)
      for (var s = 0; s < KNOWN_SHORTENERS.length; s++) {
        var shortener = KNOWN_SHORTENERS[s];
        if (hostname === shortener || hostname.endsWith('.' + shortener)) {
          firedRules.push({
            id: 'URL_SHORTENER',
            title: 'Shortened Link Concealing Destination',
            weight: 25,
            explanation: 'Shortened links hide where you are really going and prevent previewing the genuine site.'
          });
          identityReport.identityIndicators.push('Link shortener service (' + shortener + ') hides the final destination domain.');
          break;
        }
      }

      // 6. Brand Impersonation, Character Substitution & Lookalike Typosquatting Check
      var brandCheck = inspectBrandIdentity(hostname);
      identityReport.isVerifiedOfficial = brandCheck.isVerifiedOfficial;
      identityReport.verifiedBrand = brandCheck.verifiedBrand;

      if (brandCheck.isVerifiedOfficial) {
        identityReport.brandSimilarity = {
          status: 'official_match',
          brand: brandCheck.verifiedBrand,
          officialDomains: brandCheck.officialDomains,
          similarityPercent: 100,
          explanation: brandCheck.explanation
        };
        identityReport.identityIndicators.push(brandCheck.explanation);
      } else if (brandCheck.impersonatedBrand) {
        identityReport.brandSimilarity = {
          status: brandCheck.matchType,
          brand: brandCheck.impersonatedBrand,
          officialDomains: brandCheck.officialDomains,
          similarityPercent: brandCheck.similarityPercent,
          explanation: brandCheck.explanation
        };
        identityReport.identityIndicators.push(brandCheck.explanation);

        if (brandCheck.matchType === 'exact_brand_in_unofficial_domain') {
          firedRules.push({
            id: 'URL_BRAND_IMPERSONATION',
            title: 'Brand Impersonation (' + brandCheck.impersonatedBrand + ')',
            weight: 30,
            explanation: brandCheck.explanation
          });
        } else if (brandCheck.matchType === 'char_substitution') {
          firedRules.push({
            id: 'URL_CHAR_SUBSTITUTION',
            title: 'Deceptive Character Substitution (' + brandCheck.impersonatedBrand + ')',
            weight: 35,
            explanation: brandCheck.explanation
          });
        } else if (brandCheck.matchType === 'typosquatting_lookalike') {
          firedRules.push({
            id: 'URL_LOOKALIKE_DOMAIN',
            title: 'Lookalike / Misspelled Brand Domain (' + brandCheck.impersonatedBrand + ')',
            weight: 35,
            explanation: brandCheck.explanation
          });
        }
      } else {
        identityReport.brandSimilarity = {
          status: 'no_brand_match',
          brand: null,
          officialDomains: [],
          similarityPercent: 0,
          explanation: 'No direct match or lookalike similarity to tracked major Indian/global banking and payment brands.'
        };
      }

      // Known malicious domain match
      if (KNOWN_MALICIOUS_DOMAINS.indexOf(hostname) !== -1 || KNOWN_MALICIOUS_DOMAINS.indexOf(regDomain) !== -1) {
        firedRules.push({
          id: 'URL_KNOWN_PHISHING_SIGNATURE',
          title: 'Known Phishing / High-Risk Domain Pattern',
          weight: 35,
          explanation: 'This domain matches a known phishing indicator pattern in the ScamLens threat feed.'
        });
        identityReport.identityIndicators.push('Matches known high-risk phishing domain signature.');
      }

      // 7. No HTTPS (plain HTTP)
      if (protocol === 'http:') {
        firedRules.push({
          id: 'URL_NO_HTTPS',
          title: 'Insecure Connection (HTTP without SSL)',
          weight: 15,
          explanation: 'This link does not use encrypted HTTPS, meaning your connection is unverified and unprotected.'
        });
      }

      // 8. Very long URL (> 75 chars)
      if (fullHref.length > 75) {
        firedRules.push({
          id: 'URL_VERY_LONG',
          title: 'Abnormally Long URL',
          weight: 15,
          explanation: 'Extremely long URLs often pack obfuscated query parameters and tracking tokens.'
        });
      }

      // 9. Excessive hyphens (more than 2 in hostname or path)
      var hyphenCountHost = (hostname.match(/-/g) || []).length;
      var hyphenCountPath = (parsed.pathname.match(/-/g) || []).length;
      if (hyphenCountHost >= 2 || hyphenCountPath > 3) {
        firedRules.push({
          id: 'URL_EXCESSIVE_HYPHENS',
          title: 'Deceptive Hyphen Stacking',
          weight: 15,
          explanation: 'Hyphen-heavy names (e.g. paytm-secure-login-verify) are typically engineered to trick readers.'
        });
      }

      // 10. Suspicious lure keywords in path / query
      var suspiciousLureRegex = /(claim|free|cashback|reward|bonus|lucky|kyc|verify|login|gift|update|re-delivery)/i;
      if (suspiciousLureRegex.test(pathAndSearch) && !brandCheck.isVerifiedOfficial) {
        firedRules.push({
          id: 'URL_SUSPICIOUS_PATH_KEYWORDS',
          title: 'Lure Keywords in Link Address',
          weight: 20,
          explanation: 'The link path contains promotional lures like "cashback", "claim", or "verify".'
        });
      }

      // 11. Suspicious Redirect Query Parameters (e.g. ?redirect=http..., ?url=http..., ?next=http...)
      var redirectParamRegex = /[?&](redirect|redirect_uri|url|next|return|dest|destination|continue|goto)=(https?%3A%2F%2F|https?:\/\/)/i;
      if (redirectParamRegex.test(parsed.search || '')) {
        firedRules.push({
          id: 'URL_OPEN_REDIRECT_PARAM',
          title: 'Suspicious Open-Redirect Parameter in URL',
          weight: 25,
          explanation: 'This link contains an embedded redirect parameter that can forward your browser to a different untrusted site.'
        });
        identityReport.identityIndicators.push('Contains an embedded open-redirect query parameter.');
      }

      if (identityReport.identityIndicators.length === 0) {
        identityReport.identityIndicators.push('Standard domain structure (' + regDomain + '). Always verify the domain independently before entering credentials.');
      }
    }

    var result = sc.calculateScore(firedRules);
    result.maskedPreview = mask.maskPreview ? mask.maskPreview(trimmed) : trimmed.slice(0, 60);
    result.enteredUrl = trimmed;
    result.normalizedDomain = identityReport.normalizedDomain;
    result.identityReport = identityReport;

    return result;
  }

  return {
    analyzeUrl: analyzeUrl,
    inspectBrandIdentity: inspectBrandIdentity,
    getRegistrableDomain: getRegistrableDomain,
    levenshtein: levenshtein,
    SUSPICIOUS_TLDS: SUSPICIOUS_TLDS,
    KNOWN_SHORTENERS: KNOWN_SHORTENERS,
    BRAND_REGISTRY: BRAND_REGISTRY
  };
}));
