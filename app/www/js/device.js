/**
 * ScamLens Device Identity Service
 * Manages persistent anonymous device UUID using Capacitor Preferences
 * with local storage fallback.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.ScamLensDevice = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var DEVICE_KEY = 'scamlens_device_id';
  var cachedDeviceId = null;

  /**
   * Cryptographically secure or fallback UUID v4 generator
   */
  function generateUuid() {
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
      return crypto.randomUUID();
    }
    // RFC4122 v4 UUID fallback
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
      var r = (Math.random() * 16) | 0;
      var v = c === 'x' ? r : (r & 0x3) | 0x8;
      return v.toString(16);
    });
  }

  /**
   * Retrieve Capacitor Preferences plugin if available
   */
  function getPreferencesPlugin() {
    if (typeof window !== 'undefined' && window.Capacitor && window.Capacitor.Plugins && window.Capacitor.Plugins.Preferences) {
      return window.Capacitor.Plugins.Preferences;
    }
    return null;
  }

  /**
   * Get or initialize persistent Device ID
   * @returns {Promise<string>}
   */
  async function getDeviceId() {
    if (cachedDeviceId) {
      return cachedDeviceId;
    }

    var prefs = getPreferencesPlugin();

    // 1. Try Capacitor Preferences
    if (prefs) {
      try {
        var result = await prefs.get({ key: DEVICE_KEY });
        if (result && result.value) {
          cachedDeviceId = result.value;
          return cachedDeviceId;
        }
        var newId = generateUuid();
        await prefs.set({ key: DEVICE_KEY, value: newId });
        cachedDeviceId = newId;
        return cachedDeviceId;
      } catch (err) {
        console.warn('[Device] Preferences plugin read error, using storage fallback:', err);
      }
    }

    // 2. Browser LocalStorage Fallback
    if (typeof localStorage !== 'undefined') {
      try {
        var localId = localStorage.getItem(DEVICE_KEY);
        if (localId) {
          cachedDeviceId = localId;
          return cachedDeviceId;
        }
        var generated = generateUuid();
        localStorage.setItem(DEVICE_KEY, generated);
        cachedDeviceId = generated;
        return cachedDeviceId;
      } catch (e) {
        console.warn('[Device] LocalStorage access failed:', e);
      }
    }

    // 3. Ephemeral fallback
    cachedDeviceId = generateUuid();
    return cachedDeviceId;
  }

  return {
    getDeviceId: getDeviceId,
    generateUuid: generateUuid
  };
}));

