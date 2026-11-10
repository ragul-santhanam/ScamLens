/**
 * ScamLens Scoring Engine
 * Computes risk level, score, and tailored recommendations.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory(require('./config'));
  } else {
    root.ScamLensScoring = factory(root.ScamLensConfig);
  }
}(typeof self !== 'undefined' ? self : this, function (config) {
  'use strict';

  var cfg = config || (typeof window !== 'undefined' ? window.ScamLensConfig : {});

  /**
   * Determine risk tier and details from score
   * @param {number} rawScore 
   * @returns {{ level: string, label: string, note: string, color: string }}
   */
  function getRiskTier(rawScore) {
    var score = Math.max(0, Math.min(100, Math.round(rawScore || 0)));
    var thresholds = cfg.thresholds || {
      low: { min: 0, max: 24, label: 'Low Risk', note: 'No major risk indicators found', color: '#16A34A' },
      suspicious: { min: 25, max: 59, label: 'Suspicious', note: 'Exercise high caution. Several red flags detected', color: '#D97706' },
      high: { min: 60, max: 100, label: 'High Risk', note: 'Danger: Strong scam indicators found. Do not interact', color: '#B3261E' }
    };

    if (score >= thresholds.high.min) {
      return thresholds.high;
    } else if (score >= thresholds.suspicious.min) {
      return thresholds.suspicious;
    } else {
      return thresholds.low;
    }
  }

  /**
   * Score a set of fired rules
   * @param {Array<{ id: string, title: string, weight: number, explanation: string }>} firedRules 
   * @returns {{ score: number, riskLevel: string, note: string, color: string, firedRules: Array, actions: Array<string>, disclaimer: string }}
   */
  function calculateScore(firedRules) {
    var rules = Array.isArray(firedRules) ? firedRules : [];
    var totalWeight = 0;

    for (var i = 0; i < rules.length; i++) {
      var w = Number(rules[i].weight) || 0;
      totalWeight += w;
    }

    var score = Math.min(100, Math.max(0, totalWeight));
    var tier = getRiskTier(score);

    var recs = (cfg.recommendations && (
      tier.label === 'High Risk' ? cfg.recommendations.high :
      tier.label === 'Suspicious' ? cfg.recommendations.suspicious :
      cfg.recommendations.low
    )) || [];

    var cleanedFiredRules = rules.map(function (r) {
      return {
        id: r.id,
        title: r.title,
        explanation: r.explanation,
        severity: (Number(r.weight) >= 30) ? 'high' : (Number(r.weight) >= 20 ? 'medium' : 'low')
      };
    });

    var indicatorCategory = tier.indicatorCategory || (
      tier.label === 'High Risk' ? 'High Risk Indicators' :
      tier.label === 'Suspicious' ? 'Medium Risk Indicators' :
      'Low Risk Indicators'
    );

    return {
      score: score,
      riskLevel: tier.label,
      riskCategory: indicatorCategory,
      riskNote: tier.note,
      riskColor: tier.color,
      firedRules: cleanedFiredRules,
      actions: recs,
      disclaimer: cfg.disclaimer || 'ScamLens gives risk indicators, not guaranteed verdicts. Always verify independently through official channels before acting.',
      analyzedAt: new Date().toISOString()
    };
  }

  return {
    getRiskTier: getRiskTier,
    calculateScore: calculateScore
  };
}));

