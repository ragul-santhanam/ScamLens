/**
 * ScamLens Message Analysis Engine
 * Evaluates text messages against scam heuristics, urgent threat patterns,
 * OTP theft, fake KYC, and impersonation indicators.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    var defaultRules = [];
    try {
      defaultRules = require('./rules/message.json');
    } catch (e) {
      defaultRules = [];
    }
    module.exports = factory(
      require('./config'),
      require('./scoring'),
      require('./masking'),
      require('./urlAnalyzer'),
      defaultRules
    );
  } else {
    root.ScamLensMessageAnalyzer = factory(
      root.ScamLensConfig,
      root.ScamLensScoring,
      root.ScamLensMasking,
      root.ScamLensUrlAnalyzer,
      root.ScamLensRules || []
    );
  }
}(typeof self !== 'undefined' ? self : this, function (config, scoring, masking, urlAnalyzer, defaultRules) {
  'use strict';

  var cfg = config || (typeof window !== 'undefined' ? window.ScamLensConfig : {});
  var sc = scoring || (typeof window !== 'undefined' ? window.ScamLensScoring : {});
  var mask = masking || (typeof window !== 'undefined' ? window.ScamLensMasking : {});
  var urlEngine = urlAnalyzer || (typeof window !== 'undefined' ? window.ScamLensUrlAnalyzer : {});
  var activeRules = Array.isArray(defaultRules) ? defaultRules : [];

  /**
   * Set or update active message rules (e.g. when loaded asynchronously in browser)
   * @param {Array} rules 
   */
  function setRules(rules) {
    if (Array.isArray(rules)) {
      activeRules = rules;
    }
  }

  /**
   * Get active message rules
   * @returns {Array}
   */
  function getRules() {
    return activeRules;
  }

  /**
   * Analyze message text for fraud and scam indicators
   * @param {string} text - Message content to evaluate
   * @param {Array} [customRules] - Optional override rule set
   * @returns {Object} Comprehensive analysis output
   */
  function analyzeMessage(text, customRules) {
    if (!text || typeof text !== 'string') {
      var emptyRes = sc.calculateScore([]);
      emptyRes.maskedPreview = '';
      emptyRes.error = 'Invalid text input';
      return emptyRes;
    }

    var rulesToRun = Array.isArray(customRules) && customRules.length > 0 ? customRules : activeRules;
    var trimmed = text.trim();
    var lowerText = trimmed.toLowerCase();
    var firedRules = [];
    var firedRuleIds = {};

    // 1. Evaluate message rules
    for (var i = 0; i < rulesToRun.length; i++) {
      var rule = rulesToRun[i];
      var matched = false;

      if (!rule || !rule.patterns || !Array.isArray(rule.patterns)) {
        continue;
      }

      for (var p = 0; p < rule.patterns.length; p++) {
        var pattern = rule.patterns[p];
        if (rule.type === 'regex') {
          try {
            var re = new RegExp(pattern, 'i');
            if (re.test(trimmed)) {
              matched = true;
              break;
            }
          } catch (e) {
            // Ignore invalid regex syntax
          }
        } else {
          // Default: keyword / phrase match
          if (lowerText.indexOf(pattern.toLowerCase()) !== -1) {
            matched = true;
            break;
          }
        }
      }

      if (matched && !firedRuleIds[rule.id]) {
        firedRuleIds[rule.id] = true;
        firedRules.push({
          id: rule.id,
          title: rule.title,
          weight: rule.weight || 20,
          explanation: rule.explanation
        });
      }
    }

    // 2. Scan for embedded URLs within the message
    var urlRegex = /https?:\/\/[^\s]+/gi;
    var matchedUrls = trimmed.match(urlRegex) || [];

    for (var u = 0; u < matchedUrls.length; u++) {
      var detectedUrl = matchedUrls[u];
      if (urlEngine && typeof urlEngine.analyzeUrl === 'function') {
        var urlAnalysis = urlEngine.analyzeUrl(detectedUrl);
        if (urlAnalysis && Array.isArray(urlAnalysis.firedRules)) {
          for (var r = 0; r < urlAnalysis.firedRules.length; r++) {
            var uRule = urlAnalysis.firedRules[r];
            var ruleKey = 'EMBEDDED_' + uRule.id;
            if (!firedRuleIds[ruleKey] && !firedRuleIds[uRule.id]) {
              firedRuleIds[ruleKey] = true;
              // Map embedded URL weight (use proportional weight)
              var embedWeight = (uRule.id === 'URL_BRAND_IMPERSONATION' || uRule.id === 'URL_IP_HOST') ? 30 :
                                (uRule.id === 'URL_SUSPICIOUS_TLD') ? 25 :
                                (uRule.id === 'URL_SHORTENER') ? 20 : 15;

              firedRules.push({
                id: uRule.id,
                title: 'Suspicious Link: ' + uRule.title,
                weight: embedWeight,
                explanation: uRule.explanation
              });
            }
          }
        }
      }
    }

    // 3. Compute score & recommendations
    var result = sc.calculateScore(firedRules);

    // 4. Generate masked preview (never raw text)
    result.maskedPreview = mask.maskPreview ? mask.maskPreview(trimmed) : trimmed.slice(0, 60);

    return result;
  }

  return {
    analyzeMessage: analyzeMessage,
    setRules: setRules,
    getRules: getRules
  };
}));

