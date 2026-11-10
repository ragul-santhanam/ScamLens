/**
 * ScamLens Client Configuration
 * Single source of truth for API URLs, timeouts, and storage keys.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.ScamLensAppConfig = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  return {
    lanApiUrl: 'http://172.16.120.126',
    secondaryLanApiUrl: 'http://192.168.0.4',
    usbBridgeApiUrl: 'http://127.0.0.1:3000',
    emulatorApiUrl: 'http://10.0.2.2',
    localApiUrl: 'http://localhost',
    candidateApiUrls: [
      'http://127.0.0.1:3000',
      'http://192.168.137.1:3000',
      'http://192.168.137.1',
      'http://172.16.120.126:3000',
      'http://172.16.120.126',
      'http://192.168.0.4:3000',
      'http://192.168.0.4',
      'http://10.0.2.2:3000',
      'http://10.0.2.2',
      'http://localhost'
    ],

    apiBaseUrl: (function () {
      var isBrowser = typeof window !== 'undefined' && window.location;
      if (!isBrowser) return 'http://localhost'; // Node test runner
      try {
        var saved = window.localStorage && window.localStorage.getItem('scamlens_custom_api_url');
        if (saved && saved.trim()) return saved.trim().replace(/\/+$/, '');
      } catch (e) {}
      var proto = window.location.protocol;
      var isNative = !!(window.Capacitor && window.Capacitor.isNativePlatform && window.Capacitor.isNativePlatform());
      if ((proto === 'http:' || proto === 'https:') && !isNative) {
        return window.location.origin;
      }
      return 'http://127.0.0.1:3000';
    }()),

    // Documented Production Endpoint
    productionApiUrl: 'https://scamlens-api.onrender.com',

    // 5-second timeout for standard server response before triggering offline fallback
    requestTimeoutMs: 5000,
    // 25-second timeout for OCR image processing
    ocrTimeoutMs: 25000,

    // Storage keys used by Capacitor Preferences & LocalStorage
    storageKeys: {
      deviceId: 'scamlens_device_id',
      activeTab: 'scamlens_active_tab',
      authToken: 'scamlens_auth_token',
      authUser: 'scamlens_auth_user'
    }
  };
}));
