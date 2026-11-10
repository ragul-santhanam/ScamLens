/**
 * ScamLens Main Application Controller
 * Coordinates authentication, user profile, 4-tool scam detection suite
 * (Message/SMS, Website Identity, QR Code Scanner, Payment Screenshot Detector),
 * Scam Emergency Assistant, unified history, and Capacitor native plugins.
 */
(function () {
  'use strict';

  var state = {
    mode: 'message', // 'message' | 'url' | 'qr' | 'payment'
    activeTab: 'scan', // 'scan' | 'emergency' | 'history' | 'profile'
    deviceId: null,
    isOnline: true,
    user: null,
    lastResult: null,
    historyCache: [],
    historyFilter: 'all',
    selectedPaymentFile: null,
    selectedQrFile: null,
    qrStream: null,
    qrScanRaf: null,
    emergencyCategories: [],
    selectedEmergencyCat: null,
    selectedEmergencyAnswers: {}
  };

  var elements = {
    // Views
    viewScan: document.getElementById('view-scan'),
    viewEmergency: document.getElementById('view-emergency'),
    viewHistory: document.getElementById('view-history'),
    viewProfile: document.getElementById('view-profile'),

    scanForm: document.getElementById('scan-form-container'),
    resultContainer: document.getElementById('result-container'),

    // Header
    btnHeaderUser: document.getElementById('btn-header-user'),
    headerUserLabel: document.getElementById('header-user-label'),
    btnQuickEmergency: document.getElementById('btn-quick-emergency'),

    // Bottom Nav Tabs
    tabScan: document.getElementById('nav-tab-scan'),
    tabEmergency: document.getElementById('nav-tab-emergency'),
    tabHistory: document.getElementById('nav-tab-history'),
    tabProfile: document.getElementById('nav-tab-profile'),

    // Scanner Mode Toggles
    btnToggleMsg: document.getElementById('btn-toggle-msg'),
    btnToggleUrl: document.getElementById('btn-toggle-url'),
    btnToggleQr: document.getElementById('btn-toggle-qr'),
    btnTogglePayment: document.getElementById('btn-toggle-payment'),

    // Scanner Input Panels
    panelInputText: document.getElementById('panel-input-text'),
    panelInputQr: document.getElementById('panel-input-qr'),
    panelInputPayment: document.getElementById('panel-input-payment'),

    // Text/URL Input Elements
    inputLabel: document.getElementById('input-label'),
    inputText: document.getElementById('input-text'),
    charCounter: document.getElementById('char-counter'),
    btnPaste: document.getElementById('btn-paste'),
    btnAnalyze: document.getElementById('btn-analyze'),

    // QR Scanner Elements
    btnQrCameraStart: document.getElementById('btn-qr-camera-start'),
    btnQrCameraStop: document.getElementById('btn-qr-camera-stop'),
    btnQrUpload: document.getElementById('btn-qr-upload'),
    qrFileInput: document.getElementById('qr-file-input'),
    qrCameraBox: document.getElementById('qr-camera-box'),
    qrVideo: document.getElementById('qr-video'),
    qrCanvas: document.getElementById('qr-canvas'),
    qrContentInput: document.getElementById('qr-content-input'),
    btnAnalyzeQr: document.getElementById('btn-analyze-qr'),

    // Payment Screenshot Elements
    paymentDropzone: document.getElementById('payment-dropzone'),
    paymentFileInput: document.getElementById('payment-file-input'),
    paymentPreviewWrapper: document.getElementById('payment-preview-wrapper'),
    paymentPreviewImg: document.getElementById('payment-preview-img'),
    paymentFileMeta: document.getElementById('payment-file-meta'),
    btnPaymentRemove: document.getElementById('btn-payment-remove'),
    btnAnalyzePayment: document.getElementById('btn-analyze-payment'),

    // Result Actions
    btnShare: document.getElementById('btn-share'),
    btnCheckAnother: document.getElementById('btn-check-another'),

    // Emergency Assistant Elements
    emergencyCategoriesList: document.getElementById('emergency-categories-list'),
    emergencyQuestionsPanel: document.getElementById('emergency-questions-panel'),
    emergencyQuestionsContainer: document.getElementById('emergency-questions-container'),
    btnEmergencySubmit: document.getElementById('btn-emergency-submit'),
    emergencyGuidanceResult: document.getElementById('emergency-guidance-result'),
    emergencyUrgencyBadge: document.getElementById('emergency-urgency-badge'),
    emergencyResultTitle: document.getElementById('emergency-result-title'),
    emergencyStepsList: document.getElementById('emergency-steps-list'),
    emergencyDonotList: document.getElementById('emergency-donot-list'),
    emergencyHistoryList: document.getElementById('emergency-history-list'),

    // History Elements
    historyFilterBar: document.getElementById('history-filter-bar'),
    btnClearHistory: document.getElementById('btn-clear-history'),
    historyRetry: document.getElementById('btn-history-retry'),

    // Auth & Profile Elements
    authFormsContainer: document.getElementById('auth-forms-container'),
    profileDashboardContainer: document.getElementById('profile-dashboard-container'),
    cardAuthLogin: document.getElementById('card-auth-login'),
    cardAuthSignup: document.getElementById('card-auth-signup'),
    cardAuthForgot: document.getElementById('card-auth-forgot'),
    formLogin: document.getElementById('form-login'),
    formSignup: document.getElementById('form-signup'),
    formForgot: document.getElementById('form-forgot'),
    btnGoSignup: document.getElementById('btn-go-signup'),
    btnGoLogin: document.getElementById('btn-go-login'),
    btnGoForgot: document.getElementById('btn-go-forgot'),
    btnBackToLogin: document.getElementById('btn-back-to-login'),
    btnForgotSendCode: document.getElementById('btn-forgot-send-code'),
    forgotVerifySection: document.getElementById('forgot-verify-section'),
    forgotCodeBanner: document.getElementById('forgot-code-banner'),
    btnProfileViewHistory: document.getElementById('btn-profile-view-history'),
    btnLogout: document.getElementById('btn-logout')
  };

  /**
   * Initialize App
   */
  async function init() {
    try {
      state.deviceId = await ScamLensDevice.getDeviceId();
    } catch (e) {
      state.deviceId = ScamLensDevice.generateUuid();
    }

    // Restore stored auth session if present
    var storedUser = ScamLensApi.getStoredUser();
    if (storedUser && ScamLensApi.getAuthToken()) {
      state.user = storedUser;
      updateAuthUI();
    }

    bindEvents();
    await checkConnectivity();

    if (ScamLensApi.getAuthToken()) {
      refreshUserProfile();
    }

    loadEmergencyCatalog();
    setupNetworkListener();
    setInterval(checkConnectivity, 15000);
  }

  async function checkConnectivity() {
    try {
      var health = await ScamLensApi.checkHealth();
      state.isOnline = Boolean(health.isOnline);
      ScamLensUI.updateStatusChip(state.isOnline);
    } catch (err) {
      state.isOnline = false;
      ScamLensUI.updateStatusChip(false);
    }
  }

  function setupNetworkListener() {
    if (window.Capacitor && window.Capacitor.Plugins && window.Capacitor.Plugins.Network) {
      try {
        window.Capacitor.Plugins.Network.addListener('networkStatusChange', function (status) {
          if (!status.connected) {
            state.isOnline = false;
            ScamLensUI.updateStatusChip(false);
            ScamLensUI.showToast('You are currently offline');
          } else {
            checkConnectivity();
          }
        });
      } catch (e) {
        // Ignore
      }
    }
  }

  // ==================== AUTH & PROFILE CONTROLLER ====================

  function showAuthCard(which) {
    if (!elements.cardAuthLogin) return;
    elements.cardAuthLogin.style.display = which === 'login' ? 'block' : 'none';
    elements.cardAuthSignup.style.display = which === 'signup' ? 'block' : 'none';
    elements.cardAuthForgot.style.display = which === 'forgot' ? 'block' : 'none';
  }

  function updateAuthUI() {
    if (state.user) {
      var firstName = (state.user.fullName || 'Account').split(' ')[0];
      if (elements.headerUserLabel) {
        elements.headerUserLabel.textContent = firstName;
      }
      if (elements.authFormsContainer) {
        elements.authFormsContainer.style.display = 'none';
      }
      if (elements.profileDashboardContainer) {
        elements.profileDashboardContainer.style.display = 'block';
      }

      var initialsEl = document.getElementById('profile-avatar-initials');
      var nameEl = document.getElementById('profile-user-name');
      var emailEl = document.getElementById('profile-user-email');
      var mobileEl = document.getElementById('profile-user-mobile');
      var createdEl = document.getElementById('profile-user-created');

      if (initialsEl) initialsEl.textContent = (state.user.fullName || 'U').charAt(0).toUpperCase();
      if (nameEl) nameEl.textContent = state.user.fullName || 'ScamLens User';
      if (emailEl) emailEl.textContent = state.user.email || '';
      if (mobileEl) mobileEl.textContent = state.user.mobile || 'Not provided';
      if (createdEl) createdEl.textContent = ScamLensUI.formatDate(state.user.createdAt) || 'Active Member';
    } else {
      if (elements.headerUserLabel) {
        elements.headerUserLabel.textContent = 'Sign In';
      }
      if (elements.authFormsContainer) {
        elements.authFormsContainer.style.display = 'block';
      }
      if (elements.profileDashboardContainer) {
        elements.profileDashboardContainer.style.display = 'none';
      }
      showAuthCard('login');
    }
  }

  async function refreshUserProfile() {
    if (!ScamLensApi.getAuthToken()) return;
    try {
      var data = await ScamLensApi.getMe();
      if (data && data.user) {
        state.user = data.user;
        updateAuthUI();
      }
      if (data && data.stats) {
        var totalEl = document.getElementById('profile-stat-total');
        var highEl = document.getElementById('profile-stat-high');
        var emEl = document.getElementById('profile-stat-emergency');
        if (totalEl) totalEl.textContent = data.stats.totalScans || 0;
        if (highEl) highEl.textContent = data.stats.highRiskCount || 0;
        if (emEl) emEl.textContent = data.stats.emergencySessionsCount || 0;
      }
    } catch (err) {
      if (err.status === 401) {
        ScamLensApi.setAuthToken(null, null);
        state.user = null;
        updateAuthUI();
      }
    }
  }

  async function handleLoginSubmit(e) {
    e.preventDefault();
    var email = (document.getElementById('login-email').value || '').trim();
    var password = document.getElementById('login-password').value || '';
    var rememberMe = Boolean(document.getElementById('login-remember').checked);

    if (!email || !password) {
      ScamLensUI.showToast('Please enter both email and password');
      return;
    }

    var btn = document.getElementById('btn-login-submit');
    btn.disabled = true;
    try {
      var res = await ScamLensApi.login({ email: email, password: password, rememberMe: rememberMe });
      state.user = res.user;
      updateAuthUI();
      await refreshUserProfile();
      ScamLensUI.showToast('Welcome back, ' + (res.user.fullName || 'User') + '!');
      switchTab('scan');
    } catch (err) {
      ScamLensUI.showToast(err.message || 'Invalid login credentials');
    } finally {
      btn.disabled = false;
    }
  }

  async function handleSignupSubmit(e) {
    e.preventDefault();
    var fullName = (document.getElementById('signup-name').value || '').trim();
    var email = (document.getElementById('signup-email').value || '').trim();
    var mobile = (document.getElementById('signup-mobile').value || '').trim();
    var password = document.getElementById('signup-password').value || '';
    var confirmPassword = document.getElementById('signup-confirm-password').value || '';
    var acceptedTerms = Boolean(document.getElementById('signup-terms').checked);

    if (!fullName || !email || !password) {
      ScamLensUI.showToast('Please fill in all required fields');
      return;
    }
    if (password !== confirmPassword) {
      ScamLensUI.showToast('Passwords do not match');
      return;
    }
    if (!acceptedTerms) {
      ScamLensUI.showToast('Please accept the Terms & Privacy Policy');
      return;
    }

    var btn = document.getElementById('btn-signup-submit');
    btn.disabled = true;
    try {
      var res = await ScamLensApi.signup({
        fullName: fullName,
        email: email,
        mobile: mobile,
        password: password,
        confirmPassword: confirmPassword,
        acceptedTerms: acceptedTerms
      });
      state.user = res.user;
      updateAuthUI();
      await refreshUserProfile();
      ScamLensUI.showToast('Account created successfully!');
      switchTab('scan');
    } catch (err) {
      ScamLensUI.showToast(err.message || 'Could not create account');
    } finally {
      btn.disabled = false;
    }
  }

  async function handleForgotSendCode() {
    var email = (document.getElementById('forgot-email').value || '').trim();
    if (!email) {
      ScamLensUI.showToast('Please enter your registered email address');
      return;
    }

    elements.btnForgotSendCode.disabled = true;
    try {
      var res = await ScamLensApi.forgotPassword({ email: email });
      elements.forgotVerifySection.style.display = 'block';
      if (res.verificationCode && elements.forgotCodeBanner) {
        elements.forgotCodeBanner.textContent = 'Verification Code: ' + res.verificationCode + ' (Valid for 15 minutes)';
        document.getElementById('forgot-code').value = res.verificationCode;
      }
      ScamLensUI.showToast('Verification code generated!');
    } catch (err) {
      ScamLensUI.showToast(err.message || 'Failed to generate reset code');
    } finally {
      elements.btnForgotSendCode.disabled = false;
    }
  }

  async function handleForgotResetSubmit(e) {
    e.preventDefault();
    var email = (document.getElementById('forgot-email').value || '').trim();
    var code = (document.getElementById('forgot-code').value || '').trim();
    var newPassword = document.getElementById('forgot-new-password').value || '';
    var confirmPassword = document.getElementById('forgot-confirm-password').value || '';

    if (!email || !code || !newPassword) {
      ScamLensUI.showToast('Please enter the verification code and new password');
      return;
    }

    var btn = document.getElementById('btn-forgot-reset-submit');
    btn.disabled = true;
    try {
      var res = await ScamLensApi.forgotPassword({
        email: email,
        verificationCode: code,
        newPassword: newPassword,
        confirmPassword: confirmPassword
      });
      ScamLensUI.showToast(res.message || 'Password reset complete! Please log in.');
      elements.forgotVerifySection.style.display = 'none';
      showAuthCard('login');
      document.getElementById('login-email').value = email;
    } catch (err) {
      ScamLensUI.showToast(err.message || 'Password reset failed');
    } finally {
      btn.disabled = false;
    }
  }

  async function handleLogout() {
    await ScamLensApi.logout();
    state.user = null;
    updateAuthUI();
    ScamLensUI.showToast('Logged out successfully');
  }

  // ==================== SCANNER MODES (MESSAGE, URL, QR, PAYMENT) ====================

  function setMode(newMode) {
    stopQrCamera();
    state.mode = newMode;

    var modeBtns = [
      { el: elements.btnToggleMsg, mode: 'message' },
      { el: elements.btnToggleUrl, mode: 'url' },
      { el: elements.btnToggleQr, mode: 'qr' },
      { el: elements.btnTogglePayment, mode: 'payment' }
    ];
    modeBtns.forEach(function (item) {
      if (!item.el) return;
      if (item.mode === newMode) {
        item.el.classList.add('active');
      } else {
        item.el.classList.remove('active');
      }
    });

    if (elements.panelInputText) {
      elements.panelInputText.style.display = (newMode === 'message' || newMode === 'url') ? 'block' : 'none';
    }
    if (elements.panelInputQr) {
      elements.panelInputQr.style.display = newMode === 'qr' ? 'block' : 'none';
    }
    if (elements.panelInputPayment) {
      elements.panelInputPayment.style.display = newMode === 'payment' ? 'block' : 'none';
    }

    if (newMode === 'message') {
      elements.inputLabel.textContent = 'Suspicious Message Text';
      elements.inputText.placeholder = 'Paste the suspicious SMS, WhatsApp message, or email here...';
      elements.inputText.maxLength = 2000;
      updateCharCounter();
    } else if (newMode === 'url') {
      elements.inputLabel.textContent = 'Website Link & Identity Check';
      elements.inputText.placeholder = 'e.g., http://paytm-secure-login.xyz/kyc or https://sb1.co.in';
      elements.inputText.maxLength = 2048;
      updateCharCounter();
    }
  }

  function updateCharCounter() {
    var max = state.mode === 'message' ? 2000 : 2048;
    var len = (elements.inputText.value || '').length;
    elements.charCounter.textContent = len + ' / ' + max;
  }

  async function handlePaste() {
    var pasted = '';
    if (window.Capacitor && window.Capacitor.Plugins && window.Capacitor.Plugins.Clipboard) {
      try {
        var clipResult = await window.Capacitor.Plugins.Clipboard.read();
        if (clipResult && clipResult.value) pasted = clipResult.value;
      } catch (err) {}
    }

    if (!pasted && navigator.clipboard && typeof navigator.clipboard.readText === 'function') {
      try {
        pasted = await navigator.clipboard.readText();
      } catch (e) {}
    }

    if (pasted) {
      elements.inputText.value = pasted;
      updateCharCounter();
      ScamLensUI.showToast('Pasted from clipboard');
      elements.inputText.focus();
    } else {
      ScamLensUI.showToast('Clipboard is empty or permission denied');
    }
  }

  function showAnalysisResultScreen(result) {
    state.lastResult = result;
    ScamLensUI.renderResult(result, !state.isOnline || result.isOffline);
    elements.scanForm.style.display = 'none';
    elements.resultContainer.classList.add('active');
    window.scrollTo(0, 0);
    if (state.user) {
      refreshUserProfile();
    }
  }

  async function handleAnalyze() {
    var rawText = (elements.inputText.value || '').trim();
    if (!rawText) {
      ScamLensUI.showToast(state.mode === 'message' ? 'Please enter or paste a message to analyze' : 'Please enter or paste a URL to analyze');
      elements.inputText.focus();
      return;
    }

    elements.btnAnalyze.disabled = true;
    var originalBtnHtml = elements.btnAnalyze.innerHTML;
    elements.btnAnalyze.innerHTML = '<div class="spinner"></div><span>Analyzing...</span>';

    try {
      var result = null;
      if (state.mode === 'message') {
        result = await ScamLensApi.analyzeMessage(rawText, state.deviceId);
      } else {
        result = await ScamLensApi.analyzeUrl(rawText, state.deviceId);
      }
      showAnalysisResultScreen(result);
    } catch (err) {
      ScamLensUI.showToast(err.message || 'Analysis failed. Please check input.');
    } finally {
      elements.btnAnalyze.disabled = false;
      elements.btnAnalyze.innerHTML = originalBtnHtml;
    }
  }

  // ==================== QR CODE SCANNER LOGIC ====================

  async function startQrCamera() {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      ScamLensUI.showToast('Camera access is not supported in this browser. Use Upload QR Image instead.');
      return;
    }

    try {
      var stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: 'environment' },
        audio: false
      });
      state.qrStream = stream;
      elements.qrVideo.srcObject = stream;
      await elements.qrVideo.play();
      elements.qrCameraBox.classList.add('active');
      scanQrVideoFrame();
    } catch (err) {
      ScamLensUI.showToast('Camera permission denied or camera unavailable. You can upload a QR image instead.');
    }
  }

  function stopQrCamera() {
    if (state.qrScanRaf) {
      cancelAnimationFrame(state.qrScanRaf);
      state.qrScanRaf = null;
    }
    if (state.qrStream) {
      state.qrStream.getTracks().forEach(function (t) { t.stop(); });
      state.qrStream = null;
    }
    if (elements.qrVideo) {
      elements.qrVideo.srcObject = null;
    }
    if (elements.qrCameraBox) {
      elements.qrCameraBox.classList.remove('active');
    }
  }

  function scanQrVideoFrame() {
    if (!state.qrStream || !elements.qrVideo) return;
    if (elements.qrVideo.readyState === elements.qrVideo.HAVE_ENOUGH_DATA && typeof window.jsQR === 'function') {
      var canvas = elements.qrCanvas;
      var ctx = canvas.getContext('2d');
      canvas.width = elements.qrVideo.videoWidth;
      canvas.height = elements.qrVideo.videoHeight;
      ctx.drawImage(elements.qrVideo, 0, 0, canvas.width, canvas.height);
      var imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      var code = window.jsQR(imgData.data, imgData.width, imgData.height, { inversionAttempts: 'dontInvert' });
      if (code && code.data) {
        stopQrCamera();
        elements.qrContentInput.value = code.data;
        ScamLensUI.showToast('QR code captured! Tap Analyze QR Code to inspect.');
        return;
      }
    }
    state.qrScanRaf = requestAnimationFrame(scanQrVideoFrame);
  }

  function handleQrFileSelected(e) {
    var file = e.target.files && e.target.files[0];
    if (!file) return;
    state.selectedQrFile = file;

    var reader = new FileReader();
    reader.onload = function (ev) {
      var img = new Image();
      img.onload = function () {
        if (typeof window.jsQR === 'function') {
          var canvas = elements.qrCanvas;
          var ctx = canvas.getContext('2d');
          canvas.width = img.width;
          canvas.height = img.height;
          ctx.drawImage(img, 0, 0);
          var imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
          var code = window.jsQR(imgData.data, imgData.width, imgData.height, { inversionAttempts: 'attemptBoth' });
          if (code && code.data) {
            elements.qrContentInput.value = code.data;
            ScamLensUI.showToast('Decoded QR code from image!');
          } else {
            ScamLensUI.showToast('QR image selected. Tap Analyze QR Code to decode on server.');
          }
        }
      };
      img.src = ev.target.result;
    };
    reader.readAsDataURL(file);
  }

  async function handleAnalyzeQr() {
    stopQrCamera();
    var rawQr = (elements.qrContentInput.value || '').trim();

    if (!rawQr && !state.selectedQrFile) {
      ScamLensUI.showToast('Please scan a QR code, upload a QR image, or enter QR content first.');
      return;
    }

    elements.btnAnalyzeQr.disabled = true;
    var origHtml = elements.btnAnalyzeQr.innerHTML;
    elements.btnAnalyzeQr.innerHTML = '<div class="spinner"></div><span>Analyzing QR...</span>';

    try {
      var result = null;
      if (rawQr) {
        result = await ScamLensApi.analyzeQr(rawQr, state.deviceId);
      } else if (state.selectedQrFile) {
        result = await ScamLensApi.analyzeQrImage(state.selectedQrFile, state.deviceId);
        if (result && result.extractedContent) {
          elements.qrContentInput.value = result.extractedContent;
        }
      }
      showAnalysisResultScreen(result);
    } catch (err) {
      ScamLensUI.showToast(err.message || 'QR analysis failed');
    } finally {
      elements.btnAnalyzeQr.disabled = false;
      elements.btnAnalyzeQr.innerHTML = origHtml;
    }
  }

  // ==================== PAYMENT SCREENSHOT DETECTOR LOGIC ====================

  function handlePaymentFileSelected(e) {
    var file = e.target.files && e.target.files[0];
    if (!file) return;

    var validTypes = ['image/jpeg', 'image/jpg', 'image/png'];
    if (validTypes.indexOf((file.type || '').toLowerCase()) === -1 && !/\.(jpe?g|png)$/i.test(file.name)) {
      ScamLensUI.showToast('Unsupported file format. Please select a JPG, JPEG, or PNG image.');
      elements.paymentFileInput.value = '';
      return;
    }

    if (file.size > 5 * 1024 * 1024) {
      ScamLensUI.showToast('Image exceeds 5 MB maximum size.');
      elements.paymentFileInput.value = '';
      return;
    }

    state.selectedPaymentFile = file;
    var reader = new FileReader();
    reader.onload = function (ev) {
      elements.paymentPreviewImg.src = ev.target.result;
      elements.paymentFileMeta.textContent = file.name + ' (' + Math.round(file.size / 1024) + ' KB)';
      elements.paymentPreviewWrapper.classList.add('active');
    };
    reader.readAsDataURL(file);
  }

  function clearPaymentImage() {
    state.selectedPaymentFile = null;
    if (elements.paymentFileInput) elements.paymentFileInput.value = '';
    if (elements.paymentPreviewImg) elements.paymentPreviewImg.src = '';
    if (elements.paymentPreviewWrapper) elements.paymentPreviewWrapper.classList.remove('active');
  }

  async function handleAnalyzePayment() {
    if (!state.selectedPaymentFile) {
      ScamLensUI.showToast('Please select a payment screenshot image first');
      return;
    }

    elements.btnAnalyzePayment.disabled = true;
    var origHtml = elements.btnAnalyzePayment.innerHTML;
    elements.btnAnalyzePayment.innerHTML = '<div class="spinner"></div><span>Running OCR &amp; Checks...</span>';

    try {
      var result = await ScamLensApi.analyzePaymentScreenshot(state.selectedPaymentFile, state.deviceId);
      showAnalysisResultScreen(result);
    } catch (err) {
      ScamLensUI.showToast(err.message || 'Payment screenshot analysis failed');
    } finally {
      elements.btnAnalyzePayment.disabled = false;
      elements.btnAnalyzePayment.innerHTML = origHtml;
    }
  }

  // ==================== SCAM EMERGENCY ASSISTANT LOGIC ====================

  async function loadEmergencyCatalog() {
    try {
      var data = await ScamLensApi.getEmergencyGuidance();
      if (data && Array.isArray(data.categories)) {
        state.emergencyCategories = data.categories;
        renderEmergencyCategories();
      }
    } catch (e) {
      // Fallback if offline on initial load
    }
  }

  function renderEmergencyCategories() {
    if (!elements.emergencyCategoriesList) return;
    elements.emergencyCategoriesList.innerHTML = '';

    state.emergencyCategories.forEach(function (cat) {
      var card = document.createElement('button');
      card.type = 'button';
      card.className = 'emergency-option-card' + (state.selectedEmergencyCat && state.selectedEmergencyCat.id === cat.id ? ' selected' : '');
      card.innerHTML =
        '<div class="emergency-opt-num">' + cat.number + '</div>' +
        '<div>' +
          '<div class="emergency-opt-title">' + ScamLensUI.escapeHtml(cat.title) + '</div>' +
          '<div class="emergency-opt-desc">' + ScamLensUI.escapeHtml(cat.shortDesc) + '</div>' +
        '</div>';

      card.addEventListener('click', function () {
        selectEmergencyCategory(cat);
      });
      elements.emergencyCategoriesList.appendChild(card);
    });
  }

  function selectEmergencyCategory(cat) {
    state.selectedEmergencyCat = cat;
    state.selectedEmergencyAnswers = {};
    renderEmergencyCategories();

    if (!elements.emergencyQuestionsPanel || !elements.emergencyQuestionsContainer) return;
    elements.emergencyQuestionsContainer.innerHTML = '';

    var questions = Array.isArray(cat.questions) ? cat.questions : [];
    questions.forEach(function (q) {
      var block = document.createElement('div');
      block.className = 'emergency-question-block';
      var title = document.createElement('div');
      title.className = 'emergency-question-title';
      title.textContent = q.question;
      block.appendChild(title);

      var pillsRow = document.createElement('div');
      pillsRow.className = 'emergency-choice-pills';

      (q.options || []).forEach(function (optText, idx) {
        var pill = document.createElement('button');
        pill.type = 'button';
        pill.className = 'emergency-choice-pill' + (idx === 0 ? ' active' : '');
        pill.textContent = optText;
        if (idx === 0) {
          state.selectedEmergencyAnswers[q.id] = optText;
        }

        pill.addEventListener('click', function () {
          Array.from(pillsRow.children).forEach(function (c) { c.classList.remove('active'); });
          pill.classList.add('active');
          state.selectedEmergencyAnswers[q.id] = optText;
        });
        pillsRow.appendChild(pill);
      });

      block.appendChild(pillsRow);
      elements.emergencyQuestionsContainer.appendChild(block);
    });

    elements.emergencyQuestionsPanel.style.display = 'block';
  }

  async function handleEmergencySubmit() {
    if (!state.selectedEmergencyCat) {
      ScamLensUI.showToast('Please select what happened to you first');
      return;
    }

    elements.btnEmergencySubmit.disabled = true;
    try {
      var saved = await ScamLensApi.saveEmergencySession({
        incidentCategory: state.selectedEmergencyCat.id,
        selectedAnswers: state.selectedEmergencyAnswers,
        deviceId: state.deviceId
      });

      renderEmergencyGuidanceResult(saved.guidanceProvided || saved);
      loadEmergencyHistory();
      if (state.user) refreshUserProfile();
      ScamLensUI.showToast('Emergency action plan generated & saved');
    } catch (err) {
      ScamLensUI.showToast(err.message || 'Unable to generate emergency plan');
    } finally {
      elements.btnEmergencySubmit.disabled = false;
    }
  }

  function renderEmergencyGuidanceResult(guidance) {
    if (!elements.emergencyGuidanceResult || !guidance) return;
    elements.emergencyUrgencyBadge.textContent = guidance.urgencyLevel || 'CRITICAL';
    elements.emergencyResultTitle.textContent = guidance.incidentTitle || 'Emergency Response Plan';

    elements.emergencyStepsList.innerHTML = '';
    (guidance.immediateSteps || []).forEach(function (step) {
      var item = document.createElement('div');
      item.className = 'rec-item';
      item.innerHTML = '<span class="rec-bullet">' + ScamLensUI.ICONS.checkCircle + '</span>' +
        '<span>' + ScamLensUI.escapeHtml(step) + '</span>';
      elements.emergencyStepsList.appendChild(item);
    });

    elements.emergencyDonotList.innerHTML = '';
    (guidance.doNotList || []).forEach(function (dont) {
      var wCard = document.createElement('div');
      wCard.className = 'warning-card';
      wCard.innerHTML = '<div class="warning-card-desc" style="color:var(--color-risk-high); font-weight:600;">' +
        ScamLensUI.escapeHtml(dont) + '</div>';
      elements.emergencyDonotList.appendChild(wCard);
    });

    elements.emergencyGuidanceResult.style.display = 'block';
    elements.emergencyGuidanceResult.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  async function loadEmergencyHistory() {
    if (!elements.emergencyHistoryList) return;
    try {
      var list = await ScamLensApi.getEmergencyHistory(state.deviceId);
      elements.emergencyHistoryList.innerHTML = '';
      if (!Array.isArray(list) || list.length === 0) {
        elements.emergencyHistoryList.innerHTML = '<div style="font-size:12.5px; color:var(--color-ink-muted);">No emergency sessions recorded yet.</div>';
        return;
      }
      list.slice(0, 10).forEach(function (sess) {
        var card = document.createElement('div');
        card.className = 'history-card';
        card.innerHTML =
          '<div class="history-card-top">' +
            '<span class="history-badge high">' + ScamLensUI.escapeHtml((sess.guidanceProvided && sess.guidanceProvided.urgencyLevel) || 'EMERGENCY') + '</span>' +
            '<span class="history-type-chip">' + ScamLensUI.escapeHtml(ScamLensUI.formatDate(sess.createdAt)) + '</span>' +
          '</div>' +
          '<div class="history-preview">' + ScamLensUI.escapeHtml(sess.incidentTitle || sess.incidentCategory) + '</div>';
        card.addEventListener('click', function () {
          if (sess.guidanceProvided) {
            renderEmergencyGuidanceResult(Object.assign({ incidentTitle: sess.incidentTitle }, sess.guidanceProvided));
          }
        });
        elements.emergencyHistoryList.appendChild(card);
      });
    } catch (e) {
      // Ignore
    }
  }

  // ==================== RESULT ACTIONS & HISTORY ====================

  function handleCheckAnother() {
    elements.inputText.value = '';
    updateCharCounter();
    if (elements.qrContentInput) elements.qrContentInput.value = '';
    clearPaymentImage();
    elements.resultContainer.classList.remove('active');
    elements.scanForm.style.display = 'block';
    state.lastResult = null;
    window.scrollTo(0, 0);
  }

  async function handleShare() {
    if (!state.lastResult) return;

    var res = state.lastResult;
    var risk = res.riskLevel || 'Suspicious';
    var score = res.score || 0;
    var warnings = (res.firedRules || []).map(function (w) { return '• ' + w.title; }).join('\n');
    if (!warnings) warnings = '• No major risk indicators detected';

    var shareText =
      '⚠️ ScamLens Risk Assessment\n' +
      'Result: ' + risk + ' (Score: ' + score + '/100)\n\n' +
      'Detected Indicators:\n' + warnings + '\n\n' +
      'Safety Reminder:\n' +
      'Never share OTP, PIN, or CVV. Always verify transactions in your official bank/UPI app.\n' +
      'Report fraud to Cybercrime Helpline: 1930 or cybercrime.gov.in\n\n' +
      'ScamLens: See Through Scams. Stay Safe.';

    if (window.Capacitor && window.Capacitor.Plugins && window.Capacitor.Plugins.Share) {
      try {
        await window.Capacitor.Plugins.Share.share({
          title: 'ScamLens Risk Warning',
          text: shareText,
          dialogTitle: 'Share Scam Warning'
        });
        return;
      } catch (err) {}
    }

    if (navigator.share) {
      try {
        await navigator.share({ title: 'ScamLens Risk Warning', text: shareText });
        return;
      } catch (e) {}
    }

    if (navigator.clipboard && navigator.clipboard.writeText) {
      try {
        await navigator.clipboard.writeText(shareText);
        ScamLensUI.showToast('Warning summary copied to clipboard!');
      } catch (e) {
        ScamLensUI.showToast('Unable to share on this device');
      }
    }
  }

  async function loadHistory() {
    try {
      var scans = await ScamLensApi.getHistory(state.deviceId);
      state.historyCache = Array.isArray(scans) ? scans : [];
      applyHistoryFilter();
    } catch (err) {
      ScamLensUI.renderHistoryError(
        'Unable to connect to history server. Make sure the backend is running and your device has network connectivity.',
        loadHistory
      );
    }
  }

  function applyHistoryFilter() {
    var filtered = state.historyCache;
    if (state.historyFilter !== 'all') {
      filtered = state.historyCache.filter(function (s) {
        return s.type === state.historyFilter;
      });
    }
    ScamLensUI.renderHistoryList(filtered, handleHistoryCardClick, handleHistoryDeleteClick);
  }

  async function handleHistoryCardClick(scan) {
    try {
      var details = await ScamLensApi.getScanDetails(scan._id, state.deviceId);
      ScamLensUI.renderResult(details, false);
      elements.scanForm.style.display = 'none';
      elements.resultContainer.classList.add('active');
      switchTab('scan');
      window.scrollTo(0, 0);
    } catch (err) {
      ScamLensUI.showToast('Could not load scan details: ' + err.message);
    }
  }

  function handleHistoryDeleteClick(scan) {
    ScamLensUI.showConfirmModal({
      title: 'Delete Scan',
      body: 'Do you want to remove this scan from your history?',
      confirmText: 'Delete',
      onConfirm: async function () {
        try {
          await ScamLensApi.deleteScan(scan._id, state.deviceId);
          ScamLensUI.showToast('Scan deleted');
          loadHistory();
          if (state.user) refreshUserProfile();
        } catch (err) {
          ScamLensUI.showToast('Failed to delete scan: ' + err.message);
        }
      }
    });
  }

  function handleClearAllHistory() {
    ScamLensUI.showConfirmModal({
      title: 'Clear All History',
      body: 'Are you sure you want to delete all saved scans? This cannot be undone.',
      confirmText: 'Clear All',
      onConfirm: async function () {
        try {
          await ScamLensApi.clearHistory(state.deviceId);
          ScamLensUI.showToast('History cleared');
          loadHistory();
          if (state.user) refreshUserProfile();
        } catch (err) {
          ScamLensUI.showToast('Failed to clear history: ' + err.message);
        }
      }
    });
  }

  // ==================== TAB NAVIGATION ====================

  function switchTab(tabName) {
    stopQrCamera();
    state.activeTab = tabName;

    var tabMap = [
      { btn: elements.tabScan, view: elements.viewScan, name: 'scan' },
      { btn: elements.tabEmergency, view: elements.viewEmergency, name: 'emergency' },
      { btn: elements.tabHistory, view: elements.viewHistory, name: 'history' },
      { btn: elements.tabProfile, view: elements.viewProfile, name: 'profile' }
    ];

    tabMap.forEach(function (t) {
      if (t.btn) {
        if (t.name === tabName) t.btn.classList.add('active');
        else t.btn.classList.remove('active');
      }
      if (t.view) {
        if (t.name === tabName) t.view.classList.add('active');
        else t.view.classList.remove('active');
      }
    });

    if (tabName === 'history') {
      loadHistory();
    } else if (tabName === 'emergency') {
      if (state.emergencyCategories.length === 0) loadEmergencyCatalog();
      loadEmergencyHistory();
    } else if (tabName === 'profile') {
      updateAuthUI();
      if (state.user) refreshUserProfile();
    }
  }

  function bindEvents() {
    // Bottom navigation tabs
    if (elements.tabScan) elements.tabScan.addEventListener('click', function () { switchTab('scan'); });
    if (elements.tabEmergency) elements.tabEmergency.addEventListener('click', function () { switchTab('emergency'); });
    if (elements.tabHistory) elements.tabHistory.addEventListener('click', function () { switchTab('history'); });
    if (elements.tabProfile) elements.tabProfile.addEventListener('click', function () { switchTab('profile'); });

    if (elements.btnHeaderUser) {
      elements.btnHeaderUser.addEventListener('click', function () { switchTab('profile'); });
    }
    var statusChipEl = document.getElementById('network-status-pill');
    if (statusChipEl) {
      statusChipEl.style.cursor = 'pointer';
      statusChipEl.title = 'Tap to configure Server URL or retry connection';
      statusChipEl.addEventListener('click', async function () {
        var currentUrl = ScamLensApi.getBaseUrl();
        var entered = window.prompt(
          'Backend Server URL (leave as-is to retry, or enter your laptop Wi-Fi IP e.g. http://172.16.120.126:3000):',
          currentUrl
        );
        if (entered !== null && entered.trim()) {
          ScamLensApi.setBaseUrl(entered.trim(), true);
        }
        await checkConnectivity();
        ScamLensUI.showToast(state.isOnline ? ('Connected to ' + ScamLensApi.getBaseUrl()) : 'Still offline — check USB cable or Wi-Fi IP');
      });
    }
    if (elements.btnQuickEmergency) {
      elements.btnQuickEmergency.addEventListener('click', function () { switchTab('emergency'); });
    }

    // 4 Scanner Mode toggles
    if (elements.btnToggleMsg) elements.btnToggleMsg.addEventListener('click', function () { setMode('message'); });
    if (elements.btnToggleUrl) elements.btnToggleUrl.addEventListener('click', function () { setMode('url'); });
    if (elements.btnToggleQr) elements.btnToggleQr.addEventListener('click', function () { setMode('qr'); });
    if (elements.btnTogglePayment) elements.btnTogglePayment.addEventListener('click', function () { setMode('payment'); });

    // Message & URL inputs
    if (elements.inputText) elements.inputText.addEventListener('input', updateCharCounter);
    if (elements.btnPaste) elements.btnPaste.addEventListener('click', handlePaste);
    if (elements.btnAnalyze) elements.btnAnalyze.addEventListener('click', handleAnalyze);

    // QR Code inputs
    if (elements.btnQrCameraStart) elements.btnQrCameraStart.addEventListener('click', startQrCamera);
    if (elements.btnQrCameraStop) elements.btnQrCameraStop.addEventListener('click', stopQrCamera);
    if (elements.btnQrUpload) {
      elements.btnQrUpload.addEventListener('click', function () {
        if (elements.qrFileInput) elements.qrFileInput.click();
      });
    }
    if (elements.qrFileInput) elements.qrFileInput.addEventListener('change', handleQrFileSelected);
    if (elements.btnAnalyzeQr) elements.btnAnalyzeQr.addEventListener('click', handleAnalyzeQr);

    // Payment Screenshot inputs
    if (elements.paymentDropzone) {
      elements.paymentDropzone.addEventListener('click', function () {
        if (elements.paymentFileInput) elements.paymentFileInput.click();
      });
    }
    if (elements.paymentFileInput) elements.paymentFileInput.addEventListener('change', handlePaymentFileSelected);
    if (elements.btnPaymentRemove) elements.btnPaymentRemove.addEventListener('click', clearPaymentImage);
    if (elements.btnAnalyzePayment) elements.btnAnalyzePayment.addEventListener('click', handleAnalyzePayment);

    // Result actions
    if (elements.btnShare) elements.btnShare.addEventListener('click', handleShare);
    if (elements.btnCheckAnother) elements.btnCheckAnother.addEventListener('click', handleCheckAnother);

    // Emergency Assistant actions
    if (elements.btnEmergencySubmit) elements.btnEmergencySubmit.addEventListener('click', handleEmergencySubmit);

    // History filter pills & actions
    if (elements.historyFilterBar) {
      elements.historyFilterBar.addEventListener('click', function (e) {
        var pill = e.target.closest('.history-filter-pill');
        if (!pill) return;
        Array.from(elements.historyFilterBar.querySelectorAll('.history-filter-pill')).forEach(function (p) {
          p.classList.remove('active');
        });
        pill.classList.add('active');
        state.historyFilter = pill.getAttribute('data-filter') || 'all';
        applyHistoryFilter();
      });
    }
    if (elements.btnClearHistory) elements.btnClearHistory.addEventListener('click', handleClearAllHistory);
    if (elements.historyRetry) elements.historyRetry.addEventListener('click', loadHistory);

    // Auth forms & password visibility toggles
    if (elements.btnGoSignup) elements.btnGoSignup.addEventListener('click', function () { showAuthCard('signup'); });
    if (elements.btnGoLogin) elements.btnGoLogin.addEventListener('click', function () { showAuthCard('login'); });
    if (elements.btnGoForgot) elements.btnGoForgot.addEventListener('click', function () { showAuthCard('forgot'); });
    if (elements.btnBackToLogin) elements.btnBackToLogin.addEventListener('click', function () { showAuthCard('login'); });

    if (elements.formLogin) elements.formLogin.addEventListener('submit', handleLoginSubmit);
    if (elements.formSignup) elements.formSignup.addEventListener('submit', handleSignupSubmit);
    if (elements.btnForgotSendCode) elements.btnForgotSendCode.addEventListener('click', handleForgotSendCode);
    if (elements.formForgot) elements.formForgot.addEventListener('submit', handleForgotResetSubmit);

    if (elements.btnProfileViewHistory) {
      elements.btnProfileViewHistory.addEventListener('click', function () { switchTab('history'); });
    }
    if (elements.btnLogout) elements.btnLogout.addEventListener('click', handleLogout);

    // Password show/hide toggle buttons
    document.querySelectorAll('.pwd-toggle-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var targetId = btn.getAttribute('data-target');
        var input = document.getElementById(targetId);
        if (!input) return;
        if (input.type === 'password') {
          input.type = 'text';
          btn.textContent = 'Hide';
        } else {
          input.type = 'password';
          btn.textContent = 'Show';
        }
      });
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
