/**
 * ScamLens Privacy Masking Engine
 * Pure function: Ensures NO personally identifiable information, phone numbers,
 * email addresses, full URLs, or raw digits are stored or displayed in previews.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.ScamLensMasking = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var MAX_PREVIEW_LENGTH = 60;

  /**
   * Helper to extract clean domain from full URL
   * @param {string} fullUrl 
   * @returns {string} domain only
   */
  function extractDomain(fullUrl) {
    try {
      var urlStr = fullUrl.trim();
      if (!/^https?:\/\//i.test(urlStr)) {
        urlStr = 'http://' + urlStr;
      }
      var parsed = new URL(urlStr);
      return parsed.hostname || fullUrl;
    } catch (e) {
      // Fallback regex if URL constructor fails
      var match = fullUrl.match(/https?:\/\/([^\/\s:]+)/i);
      return match ? match[1] : fullUrl;
    }
  }

  /**
   * Mask a message or URL for secure preview storage
   * 1. Remove/replace email addresses
   * 2. Replace full URLs with domain only
   * 3. Remove/replace phone numbers
   * 4. Replace EVERY digit with '*'
   * 5. Truncate to maximum 60 characters
   *
   * @param {string} text - Raw input text or URL
   * @param {number} [maxLength=60] - Max output length
   * @returns {string} Sanitized preview (<= 60 chars)
   */
  function maskPreview(text, maxLength) {
    if (!text || typeof text !== 'string') {
      return '';
    }

    var limit = typeof maxLength === 'number' && maxLength > 0 ? maxLength : MAX_PREVIEW_LENGTH;
    var result = text.trim();

    // 1. Remove email addresses
    var emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/gi;
    result = result.replace(emailRegex, '[email]');

    // 2. Replace URLs with domain only
    var urlRegex = /https?:\/\/[^\s]+/gi;
    result = result.replace(urlRegex, function (matchedUrl) {
      return extractDomain(matchedUrl);
    });

    // Also handle standalone domains with paths like bit.ly/xyz or wa.me/12345
    var shortUrlRegex = /\b(bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rb\.gy|wa\.me)\/[^\s]+/gi;
    result = result.replace(shortUrlRegex, function (matched) {
      return matched.split('/')[0];
    });

    // 3. Remove phone numbers (Indian & international formats)
    // Matches +91 9876543210, +919876543210, 09876543210, 9876543210, 1800-xxx-xxxx, 98765-43210
    var phoneRegex = /(?:\+?91[\s-]?)?(?:\b[6-9]\d{4}[\s-]?\d{5}\b|\b[6-9]\d{9}\b|\b1800[\s-]?\d{3}[\s-]?\d{4}\b|\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b)/g;
    result = result.replace(phoneRegex, '[phone]');

    // 4. Replace EVERY digit with '*'
    result = result.replace(/\d/g, '*');

    // Normalize multiple spaces
    result = result.replace(/\s+/g, ' ').trim();

    // 5. Truncate to limit (max 60 chars)
    if (result.length > limit) {
      result = result.slice(0, limit - 3) + '...';
    }

    return result;
  }

  return {
    maskPreview: maskPreview,
    extractDomain: extractDomain
  };
}));

