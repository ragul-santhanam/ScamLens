/**
 * ScamLens UI Presentation Layer
 * Renders views, structured Website Identity / Payment OCR / QR reports,
 * Scam Emergency Assistant cards, User Profile, modals, and toast notifications.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.ScamLensUI = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var ICONS = {
    shield: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
    alertTriangle: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
    checkCircle: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
    trash: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>',
    share: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>',
    paste: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><rect x="8" y="2" width="8" height="4" rx="1" ry="1"/></svg>',
    lock: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>'
  };

  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    var div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
  }

  function formatDate(isoString) {
    if (!isoString) return '';
    var date = new Date(isoString);
    if (isNaN(date.getTime())) return '';

    var now = new Date();
    var isToday = now.toDateString() === date.toDateString();
    var timeStr = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

    if (isToday) {
      return 'Today, ' + timeStr;
    }
    return date.toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' }) + ' ' + timeStr;
  }

  function showToast(message) {
    var container = document.getElementById('toast-container');
    if (!container) return;

    var toast = document.createElement('div');
    toast.className = 'toast';
    toast.textContent = message;
    container.appendChild(toast);

    setTimeout(function () {
      if (toast.parentNode) {
        toast.parentNode.removeChild(toast);
      }
    }, 2600);
  }

  function updateStatusChip(isOnline) {
    var chip = document.getElementById('status-chip');
    var textSpan = document.getElementById('status-chip-text');
    if (!chip || !textSpan) return;

    if (isOnline) {
      chip.className = 'status-chip online';
      textSpan.textContent = 'Online';
    } else {
      chip.className = 'status-chip offline';
      textSpan.textContent = 'Offline mode';
    }
  }

  function rowHtml(label, value, highlightColor) {
    var valStyle = highlightColor ? ' style="color:' + highlightColor + ';"' : '';
    return '<div class="detail-grid-row">' +
      '<span class="detail-key">' + escapeHtml(label) + '</span>' +
      '<span class="detail-val"' + valStyle + '>' + escapeHtml(value) + '</span>' +
      '</div>';
  }

  /**
   * Render Structured Details for Website Identity, Payment OCR, or QR Code
   */
  function renderStructuredDetails(result) {
    var box = document.getElementById('result-structured-details');
    if (!box) return;

    box.innerHTML = '';
    box.classList.remove('active');

    var details = result.details || {};
    var identityReport = result.identityReport || details.identityReport || null;
    var extractedInfo = result.extractedInfo || details.extractedInfo || null;
    var qrDetails = result.qrDetails || details.qrDetails || null;

    var htmlParts = [];

    // 1. QR Code Breakdown
    if (qrDetails) {
      var qrTypeLabel = qrDetails.contentType === 'upi' ? 'UPI Payment Request QR' :
                        qrDetails.contentType === 'url' ? 'Website Link QR' : 'Text / Data QR';
      var qrHtml = '<div class="detail-card-header"><span>QR Code Payload Analysis</span><span style="font-size:12px; color:var(--color-primary);">' + escapeHtml(qrTypeLabel) + '</span></div>';

      if (qrDetails.contentType === 'upi' && qrDetails.paymentRecipient) {
        var p = qrDetails.paymentRecipient;
        qrHtml += rowHtml('Payee Name', p.payeeName || 'Not specified');
        qrHtml += rowHtml('Payee UPI ID (VPA)', p.payeeVpa || 'Not specified');
        qrHtml += rowHtml('Pre-Filled Amount', p.amount || 'User-entered', p.amount && p.amount !== 'User-entered amount' ? 'var(--color-risk-high)' : '');
        qrHtml += rowHtml('Transaction Note', p.transactionNote || 'None');
        qrHtml += rowHtml('Transaction Ref', p.transactionRef || 'None');
        if (p.isMandate) {
          qrHtml += rowHtml('Mandate Type', 'Recurring AutoPay Mandate', 'var(--color-risk-high)');
        }
      } else if (result.extractedContent || qrDetails.destinationUrl) {
        qrHtml += rowHtml('Decoded Content', result.extractedContent || qrDetails.destinationUrl || '');
      }

      if (qrDetails.verificationNotice) {
        qrHtml += '<div class="detail-note-box">' + escapeHtml(qrDetails.verificationNotice) + '</div>';
      }
      htmlParts.push(qrHtml);
    }

    // 2. Website Identity & Impersonation Breakdown
    if (identityReport && identityReport.normalizedDomain) {
      var idHtml = '<div class="detail-card-header" style="' + (htmlParts.length ? 'margin-top:14px;' : '') + '">' +
        '<span>Website Identity &amp; Impersonation Report</span>' +
        '</div>';

      idHtml += rowHtml('Entered URL', identityReport.enteredUrl || result.enteredUrl || '');
      idHtml += rowHtml('Normalized Domain', identityReport.normalizedDomain || '');
      idHtml += rowHtml('Registrable Domain', identityReport.registrableDomain || identityReport.normalizedDomain || '');

      var brandSim = identityReport.brandSimilarity || {};
      if (identityReport.isVerifiedOfficial) {
        idHtml += rowHtml('Brand Identity', 'Known Official Domain (' + (identityReport.verifiedBrand || '') + ')', 'var(--color-risk-low)');
      } else if (brandSim.brand) {
        idHtml += rowHtml('Suspected Target Brand', brandSim.brand + ' (' + (brandSim.similarityPercent || 90) + '% match)', 'var(--color-risk-high)');
        if (Array.isArray(brandSim.officialDomains) && brandSim.officialDomains.length > 0) {
          idHtml += rowHtml('Official Reference Domain', brandSim.officialDomains.slice(0, 2).join(', '));
        }
      } else {
        idHtml += rowHtml('Brand Similarity', 'No direct match to tracked brands');
      }

      var httpsInfo = identityReport.httpsInfo || {};
      idHtml += rowHtml(
        'HTTPS / Transport',
        httpsInfo.usesHttps ? 'HTTPS (Encrypted Transit)' : 'Plain HTTP (Unencrypted)',
        httpsInfo.usesHttps ? '' : 'var(--color-risk-suspicious)'
      );

      if (identityReport.domainIntel && identityReport.domainIntel.summary) {
        idHtml += rowHtml('Domain Age / RDAP', identityReport.domainIntel.summary);
      }

      if (identityReport.redirects) {
        var rInfo = identityReport.redirects;
        var redirectText = rInfo.hopCount > 0
          ? (rInfo.hopCount + ' redirect hop(s) -> ' + (rInfo.finalDomain || ''))
          : (rInfo.checked ? 'No redirects detected (Direct response)' : (rInfo.note || 'Not redirected'));
        idHtml += rowHtml('Redirect Check', redirectText, rInfo.crossDomainRedirect ? 'var(--color-risk-suspicious)' : '');
      }

      if (brandSim.explanation) {
        idHtml += '<div class="detail-note-box"><strong>Identity Assessment:</strong> ' + escapeHtml(brandSim.explanation) + '</div>';
      }
      idHtml += '<div class="detail-note-box">' + escapeHtml(identityReport.httpsNote || 'Note: HTTPS encryption does NOT prove that a website is legitimate or safe.') + '</div>';

      htmlParts.push(idHtml);
    }

    // 3. Payment Screenshot OCR Breakdown
    if (extractedInfo) {
      var payHtml = '<div class="detail-card-header"><span>Extracted Payment Screenshot Details</span></div>';
      payHtml += rowHtml('Detected App / Format', extractedInfo.appDetected || 'Unknown');
      payHtml += rowHtml(
        'Transaction ID / UTR',
        extractedInfo.transactionId || 'Not detected',
        (!extractedInfo.transactionId || extractedInfo.transactionId === 'Not detected') ? 'var(--color-risk-high)' : ''
      );
      payHtml += rowHtml('Payment Amount', extractedInfo.amount || 'Not detected');
      payHtml += rowHtml('Date & Time', extractedInfo.dateTime || 'Not detected');
      payHtml += rowHtml('Sender / Receiver', extractedInfo.senderReceiver || 'Not detected');
      payHtml += rowHtml(
        'Status Text Found',
        extractedInfo.paymentStatus || 'Unclear',
        (extractedInfo.paymentStatus && (extractedInfo.paymentStatus.indexOf('Pending') !== -1 || extractedInfo.paymentStatus.indexOf('Failed') !== -1 || extractedInfo.paymentStatus.indexOf('Unclear') !== -1))
          ? 'var(--color-risk-high)'
          : ''
      );
      payHtml += '<div class="detail-note-box"><strong>Important:</strong> A screenshot never proves a payment settled. Always check your official bank or UPI app transaction history directly.</div>';
      htmlParts.push(payHtml);
    }

    if (htmlParts.length > 0) {
      box.innerHTML = htmlParts.join('');
      box.classList.add('active');
    }
  }

  /**
   * Render Analysis Result into Result Screen
   */
  function renderResult(result, isOffline) {
    var riskBadge = document.getElementById('result-risk-badge');
    var riskCategoryEl = document.getElementById('result-risk-category');
    var riskNote = document.getElementById('result-risk-note');
    var meterFill = document.getElementById('result-meter-fill');
    var scoreText = document.getElementById('result-score-text');
    var timestampEl = document.getElementById('result-timestamp');
    var offlineBanner = document.getElementById('result-offline-banner');
    var warningsContainer = document.getElementById('result-warnings-container');
    var warningsCount = document.getElementById('result-warnings-count');
    var actionsContainer = document.getElementById('result-actions-container');
    var disclaimerText = document.getElementById('result-disclaimer');

    var riskLevel = result.riskLevel || 'Low Risk';
    var score = Math.max(0, Math.min(100, Math.round(result.score || 0)));

    var badgeClass = 'low';
    var badgeLabel = 'Low Risk';
    var categoryLabel = result.riskCategory || 'Low Risk Indicators';
    var displayNote = 'No major risk indicators found';

    if (riskLevel === 'High Risk') {
      badgeClass = 'high';
      badgeLabel = 'High Risk';
      categoryLabel = result.riskCategory || 'High Risk Indicators';
      displayNote = 'Danger: Strong scam indicators found. Do not interact';
    } else if (riskLevel === 'Suspicious') {
      badgeClass = 'suspicious';
      badgeLabel = 'Suspicious';
      categoryLabel = result.riskCategory || 'Medium Risk Indicators';
      displayNote = 'Exercise caution: Multiple red flags detected';
    }

    if (riskBadge) {
      riskBadge.className = 'risk-badge ' + badgeClass;
      riskBadge.textContent = badgeLabel;
    }

    if (riskCategoryEl) {
      riskCategoryEl.textContent = categoryLabel;
    }

    if (riskNote) {
      riskNote.textContent = displayNote;
    }

    if (meterFill) {
      meterFill.style.width = score + '%';
      meterFill.style.backgroundColor = badgeClass === 'high' ? '#B3261E' :
                                        badgeClass === 'suspicious' ? '#D97706' : '#16A34A';
    }

    if (scoreText) {
      scoreText.textContent = score + ' / 100';
    }

    if (timestampEl) {
      var ts = result.analyzedAt || result.createdAt || new Date().toISOString();
      timestampEl.textContent = 'Analyzed: ' + formatDate(ts);
    }

    if (offlineBanner) {
      if (isOffline || result.isOffline) {
        offlineBanner.className = 'offline-notice-banner active';
        offlineBanner.textContent = 'Offline Mode - Result checked on-device, not saved to history.';
      } else {
        offlineBanner.className = 'offline-notice-banner';
      }
    }

    // Structured details card (Identity / Payment / QR)
    renderStructuredDetails(result);

    // Warnings list
    var rules = Array.isArray(result.firedRules) ? result.firedRules : [];
    if (warningsCount) {
      warningsCount.textContent = rules.length;
    }

    if (warningsContainer) {
      warningsContainer.innerHTML = '';
      if (rules.length === 0) {
        var cleanCard = document.createElement('div');
        cleanCard.className = 'warning-card low-accent';
        cleanCard.innerHTML = '<div class="warning-card-title">No high-risk scam patterns triggered</div>' +
          '<div class="warning-card-desc">No known high-risk phrases, lookalike phishing domains, or manipulation rules fired on this input. Always verify independently before acting.</div>';
        warningsContainer.appendChild(cleanCard);
      } else {
        rules.forEach(function (r) {
          var wCard = document.createElement('div');
          var accentClass = badgeClass === 'high' ? '' : (badgeClass === 'suspicious' ? 'suspicious-accent' : 'low-accent');
          wCard.className = 'warning-card ' + accentClass;
          wCard.innerHTML = '<div class="warning-card-title">' + escapeHtml(r.title) + '</div>' +
            '<div class="warning-card-desc">' + escapeHtml(r.explanation) + '</div>';
          warningsContainer.appendChild(wCard);
        });
      }
    }

    // Recommendations list
    if (actionsContainer) {
      actionsContainer.innerHTML = '';
      var recs = Array.isArray(result.actions) ? result.actions : [];
      recs.forEach(function (act) {
        var item = document.createElement('div');
        item.className = 'rec-item';
        item.innerHTML = '<span class="rec-bullet">' + ICONS.checkCircle + '</span>' +
          '<span>' + escapeHtml(act) + '</span>';
        actionsContainer.appendChild(item);
      });
    }

    if (disclaimerText) {
      disclaimerText.textContent = result.disclaimer || 'ScamLens gives preliminary risk indicators, not guaranteed verdicts. Always verify independently through official channels before acting.';
    }
  }

  /**
   * Render History List
   */
  function renderHistoryList(scans, onCardClick, onDeleteClick) {
    var container = document.getElementById('history-items-container');
    var emptyState = document.getElementById('history-empty-state');
    var errorState = document.getElementById('history-error-state');
    var clearBtn = document.getElementById('btn-clear-history');

    if (errorState) errorState.style.display = 'none';

    if (!Array.isArray(scans) || scans.length === 0) {
      if (container) container.innerHTML = '';
      if (emptyState) emptyState.style.display = 'block';
      if (clearBtn) clearBtn.disabled = true;
      return;
    }

    if (emptyState) emptyState.style.display = 'none';
    if (clearBtn) clearBtn.disabled = false;
    if (!container) return;

    container.innerHTML = '';

    scans.forEach(function (scan) {
      var card = document.createElement('div');
      card.className = 'history-card';

      var badgeClass = scan.riskLevel === 'High Risk' ? 'high' :
                       scan.riskLevel === 'Suspicious' ? 'suspicious' : 'low';
      var badgeText = scan.riskLevel;

      var typeMap = {
        'message': 'SMS / Text',
        'url': 'Website Link',
        'qr': 'QR Code',
        'payment': 'Payment Receipt'
      };
      var typeText = typeMap[scan.type] || 'Scan';
      var dateText = formatDate(scan.createdAt);
      var previewText = escapeHtml(scan.maskedPreview || '(Empty preview)');

      card.innerHTML = 
        '<div class="history-card-top">' +
          '<span class="history-badge ' + badgeClass + '">' + escapeHtml(badgeText) + ' (' + scan.score + ')</span>' +
          '<span class="history-type-chip">' + escapeHtml(typeText) + '</span>' +
        '</div>' +
        '<div class="history-preview">' + previewText + '</div>' +
        '<div class="history-card-bottom">' +
          '<span>' + escapeHtml(dateText) + '</span>' +
          '<button class="history-delete-btn" title="Delete scan" data-id="' + escapeHtml(scan._id) + '">' +
            ICONS.trash +
          '</button>' +
        '</div>';

      card.addEventListener('click', function (e) {
        if (e.target.closest('.history-delete-btn')) return;
        if (typeof onCardClick === 'function') {
          onCardClick(scan);
        }
      });

      var delBtn = card.querySelector('.history-delete-btn');
      if (delBtn) {
        delBtn.addEventListener('click', function (e) {
          e.stopPropagation();
          if (typeof onDeleteClick === 'function') {
            onDeleteClick(scan);
          }
        });
      }

      container.appendChild(card);
    });
  }

  function renderHistoryError(errMsg, onRetry) {
    var container = document.getElementById('history-items-container');
    var emptyState = document.getElementById('history-empty-state');
    var errorState = document.getElementById('history-error-state');
    var errorDesc = document.getElementById('history-error-desc');
    var retryBtn = document.getElementById('btn-history-retry');
    var clearBtn = document.getElementById('btn-clear-history');

    if (container) container.innerHTML = '';
    if (emptyState) emptyState.style.display = 'none';
    if (clearBtn) clearBtn.disabled = true;

    if (errorDesc) {
      errorDesc.textContent = errMsg || 'Unable to connect to server. Please check your network connection.';
    }

    if (errorState) {
      errorState.style.display = 'block';
    }

    if (retryBtn) {
      retryBtn.onclick = function () {
        if (typeof onRetry === 'function') {
          onRetry();
        }
      };
    }
  }

  function showConfirmModal(opts) {
    var modal = document.getElementById('confirm-modal');
    var title = document.getElementById('confirm-modal-title');
    var body = document.getElementById('confirm-modal-body');
    var cancelBtn = document.getElementById('btn-modal-cancel');
    var confirmBtn = document.getElementById('btn-modal-confirm');

    if (!modal) return;

    if (title) title.textContent = opts.title || 'Are you sure?';
    if (body) body.textContent = opts.body || 'This action cannot be undone.';
    if (confirmBtn) {
      confirmBtn.textContent = opts.confirmText || 'Confirm';
      confirmBtn.onclick = function () {
        modal.classList.remove('active');
        if (typeof opts.onConfirm === 'function') {
          opts.onConfirm();
        }
      };
    }

    if (cancelBtn) {
      cancelBtn.onclick = function () {
        modal.classList.remove('active');
      };
    }

    modal.classList.add('active');
  }

  function hideConfirmModal() {
    var modal = document.getElementById('confirm-modal');
    if (modal) modal.classList.remove('active');
  }

  return {
    ICONS: ICONS,
    escapeHtml: escapeHtml,
    showToast: showToast,
    updateStatusChip: updateStatusChip,
    renderResult: renderResult,
    renderStructuredDetails: renderStructuredDetails,
    renderHistoryList: renderHistoryList,
    renderHistoryError: renderHistoryError,
    showConfirmModal: showConfirmModal,
    hideConfirmModal: hideConfirmModal,
    formatDate: formatDate
  };
}));
