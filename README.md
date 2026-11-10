<p align="center">
  <img src="app/www/assets/logo.png" width="110" alt="ScamLens Logo" />
</p>

<h1 align="center">ScamLens</h1>

<p align="center">
  <strong><em>"See Through Scams. Stay Safe."</em></strong><br/>
  Full-Stack Digital Scam Detection, Prevention & Emergency Assistance Mobile Application
</p>

---

**ScamLens** is a full-stack mobile security application designed to protect users against SMS phishing (smishing), lookalike brand impersonation websites, fraudulent QR codes, manipulated UPI payment screenshots, job/lottery scams, and active digital fraud emergencies.

Built with **HTML/CSS/JavaScript**, **Capacitor 6 (Android)**, **Node.js + Express.js**, and **MongoDB Atlas**, ScamLens combines an on-device rule evaluation engine with a cloud backend, OCR & QR inspection services, and strict privacy controls.

---

## 🌟 Core Full-Stack Features

### 1. 💬 Suspicious Message Analyzer (SMS / WhatsApp / Email)
- Evaluates messages against 28+ weighted heuristic rules covering urgency threats, fake KYC expiry lures, unrealistic part-time job offers, UPI collect traps, fake courier alerts, and OTP harvesting.
- **Privacy Masking (`masking.js`)**: Automatically masks 4+ digit numbers (`*`), emails (`[email]`), and phone numbers (`[phone]`) before storing any preview.

### 2. 🌐 Website URL & Brand Impersonation Checker
- **39-Brand Official Domain Registry**: Compares entered domains against verified Indian & global banking, UPI, e-commerce, and government domains (SBI, HDFC, ICICI, Axis, Paytm, PhonePe, GPay, NPCI, Amazon, India Post, Income Tax, Parivahan, etc.).
- **Lookalike & Typosquatting Detection**: Computes Levenshtein edit distance to catch subtle misspellings (`onlinesbii.co.in` vs `www.onlinesbi.sbi`).
- **Character Substitution & Homoglyphs**: Detects digit-for-letter and multi-letter spoofing (`0→o`, `1→l/i`, `rn→m`, `vv→w`, e.g., `paypa1-verify.com`).
- **Punycode / IDN Homograph Detection**: Flags `xn--` internationalized domains.
- **SSRF-Protected Live Inspection**: Inspects HTTPS/TLS certificates, multi-hop redirect chains, open-redirect query parameters, and RDAP domain registration age while blocking private/loopback/metadata IP ranges (`ssrfGuard.js`).

### 3. 📷 QR Code Scam Detector
- **Live Camera & Gallery Scanning**: Uses `getUserMedia` + `jsQR` in the mobile viewport or decodes uploaded PNG/JPG QR images on the backend.
- **Smart Payload Classification**:
  - **Website URLs**: Automatically routed through the full Website Identity & Brand Impersonation engine.
  - **UPI Payment URIs (`upi://pay`)**: Extracts Payee VPA (`pa`), Payee Name (`pn`), Amount (`am`), Note (`tn`), and Mode (`mode`), flagging *"Scan QR & enter PIN to receive refund/cashback"* scams, AutoPay mandates, and unverified high-value merchant requests.
  - **Plain Text**: Analyzed via the ScamLens Message Analyzer.
- **Safety Guarantee**: Never automatically opens extracted URLs or initiates UPI payment intents.

### 4. 🧾 Fake Payment Screenshot Detector (OCR)
- **Server-Side OCR (`tesseract.js`)**: Validates uploaded PNG/JPG/JPEG images (magic-byte verification, max 5 MB, processed in memory only) and extracts:
  - Transaction ID / 12-digit UTR / UPI Reference Number
  - Payment Amount (`₹ / INR`)
  - Date & Time
  - Sender & Receiver names / UPI IDs
  - Payment Status (`Paid`, `Completed`, `Pending`, `Failed`) & Payment App (`GPay`, `PhonePe`, `Paytm`, `BHIM`)
- **Manipulation & Fraud Checks**: Flags missing or fabricated UTR patterns (`111111111111`, `123456789012`), non-settled statuses (`Pending`/`Processing`), contradictory status keywords, unusual image aspect ratios, and **duplicate UTR reuse** across prior scans in MongoDB.

### 5. 🚨 Scam Emergency Assistant
- Interactive guided triage asking *"What happened to you?"* across **7 fraud categories**:
  1. Transferred money to a suspected scammer
  2. Shared OTP, PIN, CVV, or banking credentials
  3. Clicked a suspicious website link
  4. Installed an unknown APK / application
  5. Someone is remotely controlling or accessing the phone (`AnyDesk`, `TeamViewer`, `RustDesk`)
  6. Received a suspicious call or message (including fake "Digital Arrest" threats)
  7. Other digital fraud incidents
- Provides situation-specific action checklists and verified **Indian Cybercrime Support**:
  - **National Cybercrime Helpline**: **1930** (one-tap dialer)
  - **National Cyber Crime Reporting Portal**: [https://cybercrime.gov.in/](https://cybercrime.gov.in/)
  - **Sanchar Saathi (DoT)**: [https://sancharsaathi.gov.in/](https://sancharsaathi.gov.in/)
- Persists emergency sessions in MongoDB without collecting sensitive banking secrets.

### 6. 🔐 User Authentication & Isolated Profile History
- Complete Sign Up, Login, Logout, User Profile Dashboard, and 2-step Verification Code Password Reset flow.
- Passwords hashed with `bcryptjs` (12 salt rounds); protected routes authenticated via `jsonwebtoken` (JWT) with server-side logout token revocation.
- Strict per-user (`userId`) and per-device (`deviceId`) data isolation across all scan histories.

---

## 🔌 Backend API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Health check, active feature list, and MongoDB connection status |
| `POST` | `/api/auth/signup` | Register user account with `bcryptjs` password hashing & JWT |
| `POST` | `/api/auth/login` | Authenticate user and issue JWT (`7d` or `30d` with Remember Me) |
| `POST` | `/api/auth/logout` | Revoke active JWT access token |
| `POST` | `/api/auth/forgot-password` | Two-step password reset code generation & verification |
| `GET` | `/api/auth/me` | Protected user profile, scan statistics, and recent history |
| `POST` | `/api/analyze/message` | Analyze suspicious SMS/WhatsApp/email message |
| `POST` | `/api/analyze/url` | Analyze URL with Website Identity & Brand Impersonation engine |
| `POST` | `/api/qr/analyze` | Decode and analyze QR payload or uploaded QR image |
| `GET` | `/api/qr/history` | Retrieve saved QR scan history for user/device |
| `POST` | `/api/payment/analyze` | OCR and heuristic analysis of uploaded UPI/bank screenshot |
| `GET` | `/api/payment/history` | Retrieve saved payment screenshot scan history |
| `GET` | `/api/emergency/guidance` | Retrieve incident categories & tailored emergency response steps |
| `POST` | `/api/emergency/session` | Save completed emergency assistance session |
| `GET` | `/api/emergency/history` | Retrieve user's saved emergency assistance sessions |
| `GET/DELETE` | `/api/history` | Unified scan history retrieval, single-item delete, and clear all |

---

## 📁 Folder Structure

```text
scamlens/
├── shared/                              # Shared pure-JS analysis engine (Node & Browser)
│   ├── config.js                        # Risk thresholds, severities, and limits
│   ├── scoring.js                       # Weight summation & risk tier calculation
│   ├── masking.js                       # Privacy masking engine (digits, emails, phones)
│   ├── messageAnalyzer.js               # Heuristic evaluator for text messages
│   ├── urlAnalyzer.js                   # URL validation, 39-brand registry & spoof detection
│   └── rules/
│       └── message.json                 # Categorized fraud rules (weights 1-30)
├── server/                              # Node.js + Express backend
│   ├── app.js                           # Express entrypoint + USB/Wi-Fi mobile bridge
│   ├── .env.example                     # Environment variables template
│   ├── controllers/                     # Route controllers (auth, qr, payment, emergency)
│   ├── services/                        # Business logic (urlIdentity, qrAnalyzer, paymentOcr, emergency)
│   ├── utils/
│   │   └── ssrfGuard.js                 # SSRF protection for live URL/TLS/RDAP checks
│   ├── models/                          # Mongoose schemas + resilient in-memory fallback stores
│   │   ├── User.js
│   │   ├── Scan.js
│   │   ├── MessageScan.js
│   │   ├── URLScan.js
│   │   ├── QRScan.js
│   │   ├── PaymentScreenshotScan.js
│   │   └── EmergencySession.js
│   ├── routes/                          # Express routers (health, auth, analyze, qr, payment, emergency, history)
│   └── middleware/                      # JWT auth, express-validator, rateLimiter, errorHandler
├── app/                                 # Mobile frontend web assets
│   └── www/
│       ├── index.html                   # Mobile-first SPA interface
│       ├── assets/                      # ScamLens branding logos & icons
│       ├── css/
│       │   └── style.css                # ScamLens Design System (#0D6269, #8BE5D8, #FFFFFF)
│       └── js/
│           ├── config.js                # API URLs, timeouts & candidate auto-discovery
│           ├── device.js                # Capacitor Preferences deviceId manager
│           ├── api.js                   # Client API service with parallel server discovery & offline fallback
│           ├── ui.js                    # DOM rendering for all 5 feature views & reports
│           ├── app.js                   # Main application controller
│           ├── vendor/jsQR.js           # Bundled QR decoding library
│           └── engine/                  # Synced from shared/ by scripts/sync-engine.js
├── android/                             # Native Android project (Capacitor 6)
├── scripts/
│   ├── sync-engine.js                   # Syncs shared/ -> app/www/ -> www/ & android/
│   └── generate-brand-assets.js         # Generates header logos, Android mipmaps & splash screens
├── tests/
│   ├── samples.json                     # 20 benchmark messages & 8 URLs
│   ├── runTests.js                      # Shared engine unit benchmark (28/28 checks)
│   ├── e2e.js                           # Core server E2E test suite (6/6 checks)
│   ├── app-api.test.js                  # Client API integration suite (5/5 checks)
│   └── full-stack-features.test.js      # Full-stack 5-feature verification suite (30/30 checks)
├── capacitor.config.json
├── package.json
└── README.md
```

---

## 🚀 Quickstart & Installation

### 1. Install Dependencies
```bash
npm install
```

### 2. Configure Environment (`.env`)
Create a `.env` file in the project root:
```bash
cp server/.env.example .env
```
Edit `.env` with your MongoDB Atlas connection string and JWT secret:
```env
PORT=80
MONGODB_URI=mongodb+srv://<username>:<password>@cluster0.mongodb.net/scamlens?retryWrites=true&w=majority
JWT_SECRET=your_super_secret_jwt_key
NODE_ENV=development
```
*(Note: If `MONGODB_URI` is omitted or unreachable, ScamLens automatically operates on its resilient in-memory fallback store without crashing).*

### 3. Synchronize Engine & Android Assets
```bash
npm run cap:sync
```

### 4. Start the Backend Server
```bash
npm start
```
- **On your laptop**: Open `http://localhost`
- **On your phone (Wi-Fi)**: Open the Wi-Fi IP printed in the terminal (e.g., `http://192.168.x.x`)
- **On your phone (USB cable)**: Automatically tunnels via `adb reverse tcp:3000 tcp:3000` (`http://127.0.0.1:3000`)

---

## 🧪 Running the Test Suites

| Test Suite | Command | Coverage |
| :--- | :--- | :--- |
| **Rule Accuracy Benchmark** | `npm test` | **28/28 passed (100% accuracy)** across 20 messages & 8 URLs |
| **Full-Stack 5-Feature Suite** | `npm run test:fullstack` | **30/30 passed** (Auth, URL Identity, QR, Payment OCR, Emergency, Access Control) |
| **Server E2E Suite** | `npm run test:e2e` | **6/6 passed** (Health, Masking, Device Isolation, Validation) |
| **Client API Integration** | `npm run test:api` | **5/5 passed** (`api.js` client to Express backend) |

---

## 📱 Building & Running on Android (Android Studio)

1. Sync web assets and Capacitor plugins:
   ```bash
   npm run cap:sync
   ```
2. Open the Android project in Android Studio:
   ```bash
   npx cap open android
   ```
3. In **Android Studio**:
   - **Run directly on USB-connected phone or Emulator**: Select your device in the top toolbar and click **Run (▶)**.
   - **Build installable APK**: Click **Build → Build Bundle(s) / APK(s) → Build APK(s)**. The generated APK is located at:
     `android/app/build/outputs/apk/debug/app-debug.apk`

---

## 🛡️ Security & Privacy Principles

1. **Zero Raw Text or Raw Image Retention**: Raw messages are masked (`maskPreview`), and uploaded payment screenshots / QR images are processed strictly in RAM (`multer.memoryStorage()`) and discarded immediately after analysis.
2. **Password & Token Security**: User passwords are never stored in plaintext (`bcryptjs` 12 rounds), and JWT tokens support immediate revocation on logout.
3. **SSRF Protection**: Live URL redirect and certificate inspection blocks loopback (`127.0.0.0/8`), private LAN (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local (`169.254.0.0/16`), and cloud metadata endpoints.
4. **Honest Verdicts & Mandatory Disclaimers**: Never claims a message, URL, QR code, or payment screenshot is 100% "Safe" or "Genuine" — always instructs users to verify transactions in their official banking/UPI application.
