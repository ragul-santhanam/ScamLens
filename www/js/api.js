/**
 * ScamLens Client API Service
 * Handles all backend communications, JWT authentication headers, request timeouts,
 * and automatic offline engine fallback when network is unreachable.
 * Pure JS: Free of DOM dependencies, importable in both Node.js and mobile webviews.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory(
      require('./config'),
      require('./engine/messageAnalyzer'),
      require('./engine/urlAnalyzer')
    );
  } else {
    root.ScamLensApi = factory(
      root.ScamLensAppConfig,
      root.ScamLensMessageAnalyzer,
      root.ScamLensUrlAnalyzer
    );
  }
}(typeof self !== 'undefined' ? self : this, function (config, messageAnalyzer, urlAnalyzer) {
  'use strict';

  var cfg = config || (typeof window !== 'undefined' && window.ScamLensAppConfig) || {
    apiBaseUrl: 'http://localhost',
    requestTimeoutMs: 5000,
    ocrTimeoutMs: 25000
  };

  var baseUrl = cfg.apiBaseUrl || 'http://localhost';
  var timeoutMs = cfg.requestTimeoutMs || 5000;
  var ocrTimeoutMs = cfg.ocrTimeoutMs || 25000;
  var authToken = null;

  var TOKEN_KEY = (cfg.storageKeys && cfg.storageKeys.authToken) || 'scamlens_auth_token';
  var USER_KEY = (cfg.storageKeys && cfg.storageKeys.authUser) || 'scamlens_auth_user';

  // Restore saved token in browser environment
  if (typeof localStorage !== 'undefined') {
    try {
      authToken = localStorage.getItem(TOKEN_KEY) || null;
    } catch (e) {
      authToken = null;
    }
  }

  var msgEngine = messageAnalyzer || (typeof window !== 'undefined' && window.ScamLensMessageAnalyzer);
  var urlEngine = urlAnalyzer || (typeof window !== 'undefined' && window.ScamLensUrlAnalyzer);

  function setBaseUrl(url, persistCustom) {
    if (typeof url === 'string' && url.trim()) {
      var normalized = url.trim().replace(/\/+$/, '');
      if (!/^https?:\/\//i.test(normalized)) {
        normalized = 'http://' + normalized;
      }
      baseUrl = normalized;
      if (persistCustom && typeof localStorage !== 'undefined') {
        try {
          localStorage.setItem('scamlens_custom_api_url', normalized);
        } catch (e) {}
      }
    }
  }

  function getBaseUrl() {
    return baseUrl;
  }

  function setAuthToken(token, userObj) {
    authToken = token || null;
    if (typeof localStorage !== 'undefined') {
      try {
        if (token) {
          localStorage.setItem(TOKEN_KEY, token);
          if (userObj) {
            localStorage.setItem(USER_KEY, JSON.stringify(userObj));
          }
        } else {
          localStorage.removeItem(TOKEN_KEY);
          localStorage.removeItem(USER_KEY);
        }
      } catch (e) {
        // Ignore storage errors
      }
    }
  }

  function getAuthToken() {
    return authToken;
  }

  function getStoredUser() {
    if (typeof localStorage !== 'undefined') {
      try {
        var raw = localStorage.getItem(USER_KEY);
        return raw ? JSON.parse(raw) : null;
      } catch (e) {
        return null;
      }
    }
    return null;
  }

  function buildHeaders(extraHeaders, isMultipart) {
    var headers = Object.assign({}, extraHeaders || {});
    if (!isMultipart && !headers['Content-Type']) {
      headers['Content-Type'] = 'application/json';
    }
    if (authToken) {
      headers['Authorization'] = 'Bearer ' + authToken;
    }
    return headers;
  }

  async function fetchWithTimeout(url, options, ms) {
    var timeoutDuration = ms || timeoutMs;
    var controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
    var timeoutId = null;

    var fetchOpts = Object.assign({}, options);
    if (controller) {
      fetchOpts.signal = controller.signal;
      timeoutId = setTimeout(function () {
        controller.abort();
      }, timeoutDuration);
    }

    try {
      var response = await fetch(url, fetchOpts);
      if (timeoutId) clearTimeout(timeoutId);
      return response;
    } catch (err) {
      if (timeoutId) clearTimeout(timeoutId);
      throw err;
    }
  }

  async function parseJsonResponse(res, defaultErrMsg) {
    var data = await res.json().catch(function () { return {}; });
    if (!res.ok) {
      var err = new Error(data.error || defaultErrMsg || 'Request failed');
      err.status = res.status;
      throw err;
    }
    return data;
  }

  /**
   * Check Server Health & DB status (probes USB 127.0.0.1:3000, Wi-Fi IPs, Emulator 10.0.2.2, and localhost in parallel)
   */
  async function checkHealth() {
    var candidates = [baseUrl];
    if (typeof window !== 'undefined') {
      try {
        var customUrl = window.localStorage && window.localStorage.getItem('scamlens_custom_api_url');
        if (customUrl && candidates.indexOf(customUrl) === -1) {
          candidates.unshift(customUrl);
        }
      } catch (e) {}

      var extraList = (cfg && Array.isArray(cfg.candidateApiUrls))
        ? cfg.candidateApiUrls
        : ['http://127.0.0.1:3000', 'http://172.16.120.126:3000', 'http://172.16.120.126', 'http://192.168.0.4:3000', 'http://192.168.0.4', 'http://10.0.2.2:3000', 'http://10.0.2.2', 'http://localhost'];
      for (var c = 0; c < extraList.length; c++) {
        if (candidates.indexOf(extraList[c]) === -1) {
          candidates.push(extraList[c]);
        }
      }
    }

    var probeCandidate = function (candidate) {
      return fetchWithTimeout(candidate + '/api/health', { method: 'GET' }, 2500)
        .then(function (res) {
          if (!res.ok) throw new Error('HTTP ' + res.status);
          return res.json();
        })
        .then(function (json) {
          if (json && json.status === 'ok') {
            return { candidate: candidate, json: json };
          }
          throw new Error('Invalid health payload');
        });
    };

    try {
      var winner = await new Promise(function (resolve, reject) {
        var pending = candidates.length;
        var lastError = null;
        var resolved = false;
        candidates.forEach(function (cand) {
          probeCandidate(cand).then(function (result) {
            if (!resolved) {
              resolved = true;
              resolve(result);
            }
          }).catch(function (err) {
            lastError = err;
            pending--;
            if (pending === 0 && !resolved) {
              reject(lastError || new Error('Server unreachable'));
            }
          });
        });
      });

      baseUrl = winner.candidate;
      return {
        status: winner.json.status || 'ok',
        db: winner.json.db || 'disconnected',
        isOnline: true,
        activeServer: winner.candidate
      };
    } catch (err) {
      return {
        status: 'offline',
        db: 'disconnected',
        isOnline: false,
        error: err ? err.message : 'Server unreachable'
      };
    }
  }

  // ==================== AUTHENTICATION ====================

  async function signup(payload) {
    var res = await fetchWithTimeout(
      baseUrl + '/api/auth/signup',
      {
        method: 'POST',
        headers: buildHeaders(),
        body: JSON.stringify(payload)
      },
      timeoutMs
    );
    var data = await parseJsonResponse(res, 'Failed to create account');
    if (data.token) {
      setAuthToken(data.token, data.user);
    }
    return data;
  }

  async function login(payload) {
    var res = await fetchWithTimeout(
      baseUrl + '/api/auth/login',
      {
        method: 'POST',
        headers: buildHeaders(),
        body: JSON.stringify(payload)
      },
      timeoutMs
    );
    var data = await parseJsonResponse(res, 'Login failed');
    if (data.token) {
      setAuthToken(data.token, data.user);
    }
    return data;
  }

  async function logout() {
    try {
      if (authToken) {
        await fetchWithTimeout(
          baseUrl + '/api/auth/logout',
          {
            method: 'POST',
            headers: buildHeaders()
          },
          3000
        );
      }
    } catch (e) {
      // Clear local session regardless of network state
    }
    setAuthToken(null, null);
    return { success: true };
  }

  async function forgotPassword(payload) {
    var res = await fetchWithTimeout(
      baseUrl + '/api/auth/forgot-password',
      {
        method: 'POST',
        headers: buildHeaders(),
        body: JSON.stringify(payload)
      },
      timeoutMs
    );
    return await parseJsonResponse(res, 'Password reset request failed');
  }

  async function getMe() {
    var res = await fetchWithTimeout(
      baseUrl + '/api/auth/me',
      {
        method: 'GET',
        headers: buildHeaders()
      },
      timeoutMs
    );
    var data = await parseJsonResponse(res, 'Unable to load profile');
    if (data.user) {
      setAuthToken(authToken, data.user);
    }
    return data;
  }

  // ==================== MESSAGE & URL ANALYSIS ====================

  async function analyzeMessage(text, deviceId) {
    try {
      var res = await fetchWithTimeout(
        baseUrl + '/api/analyze/message',
        {
          method: 'POST',
          headers: buildHeaders(),
          body: JSON.stringify({ text: text, deviceId: deviceId })
        },
        timeoutMs
      );

      if (res.ok) {
        var data = await res.json();
        data.isOffline = false;
        return data;
      }
      if (res.status === 400) {
        var errBody = await res.json().catch(function () { return {}; });
        var badRequestError = new Error(errBody.error || 'Invalid request payload');
        badRequestError.status = 400;
        throw badRequestError;
      }
    } catch (netErr) {
      if (netErr.status === 400) throw netErr;
      console.warn('[API] Server unreachable for message analysis, falling back to on-device engine:', netErr.message);
    }

    if (msgEngine && typeof msgEngine.analyzeMessage === 'function') {
      var localResult = msgEngine.analyzeMessage(text);
      localResult.scanId = null;
      localResult.type = 'message';
      localResult.isOffline = true;
      localResult.offlineNote = 'Not saved to history (Offline Mode)';
      return localResult;
    }

    throw new Error('Analysis engine is unavailable.');
  }

  async function analyzeUrl(url, deviceId) {
    try {
      var res = await fetchWithTimeout(
        baseUrl + '/api/analyze/url',
        {
          method: 'POST',
          headers: buildHeaders(),
          body: JSON.stringify({ url: url, deviceId: deviceId })
        },
        timeoutMs + 2000
      );

      if (res.ok) {
        var data = await res.json();
        data.isOffline = false;
        return data;
      }
      if (res.status === 400) {
        var errBody = await res.json().catch(function () { return {}; });
        var badRequestError = new Error(errBody.error || 'Invalid URL payload');
        badRequestError.status = 400;
        throw badRequestError;
      }
    } catch (netErr) {
      if (netErr.status === 400) throw netErr;
      console.warn('[API] Server unreachable for URL analysis, falling back to on-device engine:', netErr.message);
    }

    if (urlEngine && typeof urlEngine.analyzeUrl === 'function') {
      var localResult = urlEngine.analyzeUrl(url);
      localResult.scanId = null;
      localResult.type = 'url';
      localResult.isOffline = true;
      localResult.offlineNote = 'Not saved to history (Offline Mode)';
      return localResult;
    }

    throw new Error('Analysis engine is unavailable.');
  }

  // ==================== QR CODE DETECTOR ====================

  async function analyzeQr(qrContent, deviceId) {
    var res = await fetchWithTimeout(
      baseUrl + '/api/qr/analyze',
      {
        method: 'POST',
        headers: buildHeaders(),
        body: JSON.stringify({ qrContent: qrContent, deviceId: deviceId })
      },
      timeoutMs + 2000
    );
    return await parseJsonResponse(res, 'Failed to analyze QR code');
  }

  async function analyzeQrImage(file, deviceId) {
    var formData = new FormData();
    formData.append('image', file);
    if (deviceId) formData.append('deviceId', deviceId);

    var res = await fetchWithTimeout(
      baseUrl + '/api/qr/analyze',
      {
        method: 'POST',
        headers: buildHeaders({}, true),
        body: formData
      },
      timeoutMs + 3000
    );
    return await parseJsonResponse(res, 'Failed to decode and analyze QR image');
  }

  async function getQrHistory(deviceId) {
    var qs = deviceId ? '?deviceId=' + encodeURIComponent(deviceId) : '';
    var res = await fetchWithTimeout(
      baseUrl + '/api/qr/history' + qs,
      { method: 'GET', headers: buildHeaders() },
      timeoutMs
    );
    return await parseJsonResponse(res, 'Failed to load QR history');
  }

  // ==================== PAYMENT SCREENSHOT DETECTOR ====================

  async function analyzePaymentScreenshot(file, deviceId) {
    var formData = new FormData();
    formData.append('image', file);
    if (deviceId) formData.append('deviceId', deviceId);

    var res = await fetchWithTimeout(
      baseUrl + '/api/payment/analyze',
      {
        method: 'POST',
        headers: buildHeaders({}, true),
        body: formData
      },
      ocrTimeoutMs
    );
    return await parseJsonResponse(res, 'Failed to analyze payment screenshot');
  }

  async function getPaymentHistory(deviceId) {
    var qs = deviceId ? '?deviceId=' + encodeURIComponent(deviceId) : '';
    var res = await fetchWithTimeout(
      baseUrl + '/api/payment/history' + qs,
      { method: 'GET', headers: buildHeaders() },
      timeoutMs
    );
    return await parseJsonResponse(res, 'Failed to load payment screenshot history');
  }

  // ==================== SCAM EMERGENCY ASSISTANT ====================

  async function getEmergencyGuidance(category) {
    var qs = category ? '?category=' + encodeURIComponent(category) : '';
    var res = await fetchWithTimeout(
      baseUrl + '/api/emergency/guidance' + qs,
      { method: 'GET', headers: buildHeaders() },
      timeoutMs
    );
    return await parseJsonResponse(res, 'Failed to load emergency guidance');
  }

  async function saveEmergencySession(payload) {
    var res = await fetchWithTimeout(
      baseUrl + '/api/emergency/session',
      {
        method: 'POST',
        headers: buildHeaders(),
        body: JSON.stringify(payload)
      },
      timeoutMs
    );
    return await parseJsonResponse(res, 'Failed to save emergency session');
  }

  async function getEmergencyHistory(deviceId) {
    var qs = deviceId ? '?deviceId=' + encodeURIComponent(deviceId) : '';
    var res = await fetchWithTimeout(
      baseUrl + '/api/emergency/history' + qs,
      { method: 'GET', headers: buildHeaders() },
      timeoutMs
    );
    return await parseJsonResponse(res, 'Failed to load emergency session history');
  }

  // ==================== UNIFIED SCAN HISTORY ====================

  async function getHistory(deviceId) {
    var qs = deviceId ? '?deviceId=' + encodeURIComponent(deviceId) : '';
    var res = await fetchWithTimeout(
      baseUrl + '/api/history' + qs,
      { method: 'GET', headers: buildHeaders() },
      timeoutMs
    );
    return await parseJsonResponse(res, 'Failed to load history');
  }

  async function getScanDetails(scanId, deviceId) {
    var qs = deviceId ? '?deviceId=' + encodeURIComponent(deviceId) : '';
    var res = await fetchWithTimeout(
      baseUrl + '/api/history/' + encodeURIComponent(scanId) + qs,
      { method: 'GET', headers: buildHeaders() },
      timeoutMs
    );
    return await parseJsonResponse(res, 'Scan not found');
  }

  async function deleteScan(scanId, deviceId) {
    var qs = deviceId ? '?deviceId=' + encodeURIComponent(deviceId) : '';
    var res = await fetchWithTimeout(
      baseUrl + '/api/history/' + encodeURIComponent(scanId) + qs,
      { method: 'DELETE', headers: buildHeaders() },
      timeoutMs
    );
    return await parseJsonResponse(res, 'Failed to delete scan');
  }

  async function clearHistory(deviceId) {
    var qs = deviceId ? '?deviceId=' + encodeURIComponent(deviceId) : '';
    var res = await fetchWithTimeout(
      baseUrl + '/api/history' + qs,
      { method: 'DELETE', headers: buildHeaders() },
      timeoutMs
    );
    return await parseJsonResponse(res, 'Failed to clear history');
  }

  return {
    setBaseUrl: setBaseUrl,
    getBaseUrl: getBaseUrl,
    setAuthToken: setAuthToken,
    getAuthToken: getAuthToken,
    getStoredUser: getStoredUser,
    checkHealth: checkHealth,
    signup: signup,
    login: login,
    logout: logout,
    forgotPassword: forgotPassword,
    getMe: getMe,
    analyzeMessage: analyzeMessage,
    analyzeUrl: analyzeUrl,
    analyzeQr: analyzeQr,
    analyzeQrImage: analyzeQrImage,
    getQrHistory: getQrHistory,
    analyzePaymentScreenshot: analyzePaymentScreenshot,
    getPaymentHistory: getPaymentHistory,
    getEmergencyGuidance: getEmergencyGuidance,
    saveEmergencySession: saveEmergencySession,
    getEmergencyHistory: getEmergencyHistory,
    getHistory: getHistory,
    getScanDetails: getScanDetails,
    deleteScan: deleteScan,
    clearHistory: clearHistory
  };
}));
