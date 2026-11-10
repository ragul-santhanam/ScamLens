/**
 * ScamLens Scam Emergency Assistant Service
 * Provides interactive triage questions, situation-specific emergency response steps,
 * and verified Indian Cybercrime reporting resources (1930 & cybercrime.gov.in).
 */

const OFFICIAL_INDIAN_RESOURCES = {
  helplineNumber: '1930',
  helplineDescription: 'National Cybercrime Helpline (24x7 Toll-Free in India). Call immediately during the "Golden Hour" to freeze fraudulent fund transfers across banks and UPI wallets.',
  reportingPortal: 'https://cybercrime.gov.in/',
  reportingPortalDescription: 'Official Ministry of Home Affairs (MHA) National Cyber Crime Reporting Portal for filing formal financial and digital fraud complaints.',
  telecomPortal: 'https://sancharsaathi.gov.in/',
  telecomPortalDescription: 'Department of Telecommunications (DoT) Sanchar Saathi (Chakshu) portal to report scam calls/SMS and block lost/compromised mobile connections.',
  bankEmergencyNote: 'Immediately call the official 24x7 customer care number printed on the back of your debit/credit card or inside your official banking app—never call numbers found via web search or social media.'
};

const INCIDENT_CATEGORIES = [
  {
    id: 'money_transfer',
    number: 1,
    title: 'I transferred money to a suspected scammer',
    shortDesc: 'Sent money via UPI, IMPS, NEFT, card, or wallet to a fraudulent account or QR code.',
    urgencyLevel: 'CRITICAL - ACT WITHIN THE GOLDEN HOUR',
    questions: [
      {
        id: 'timeElapsed',
        question: 'When did the transaction take place?',
        options: ['Within the last 1 hour', 'Today (1–24 hours ago)', 'More than 24 hours ago']
      },
      {
        id: 'paymentMethod',
        question: 'How was the money transferred?',
        options: ['UPI (PhonePe / GPay / Paytm / BHIM)', 'Bank Transfer (IMPS / NEFT / RTGS)', 'Debit / Credit Card', 'Other Wallet']
      }
    ],
    immediateSteps: [
      'DIAL 1930 IMMEDIATELY: Call the National Cybercrime Helpline (1930) right now so the Citizen Financial Cyber Fraud Reporting and Management System (CFCFRMS) can place a hold/lien on the scammer\'s receiving bank account before the money is withdrawn.',
      'CONTACT YOUR BANK / UPI APP: Report the unauthorized or fraudulent transaction inside your UPI app (Help -> Report a Fraud) and call your bank\'s official 24x7 fraud hotline to request a transaction dispute/chargeback and freeze compromised channels.',
      'PRESERVE ALL EVIDENCE: Take screenshots of the 12-digit UPI UTR / Bank Reference Number, the scammer\'s UPI ID or bank account details, phone numbers, chat logs, and your bank debit SMS. Do NOT delete the chat or call history.',
      'FILE OFFICIAL REPORT AT CYBERCRIME.GOV.IN: Visit https://cybercrime.gov.in/, select "Report Financial Fraud", and upload your transaction reference (UTR), bank statement excerpt, and screenshots.'
    ],
    doNotList: [
      'DO NOT search Google or social media for "UPI refund helpline" or "cybercrime customer care number"—scammers run fake recovery ads to steal more money.',
      'DO NOT scan any "refund QR code" or enter your UPI PIN to "reverse" the transaction.',
      'DO NOT pay any "processing fee" or "recovery fee" to anyone promising to get your money back.'
    ]
  },
  {
    id: 'otp_pin_shared',
    number: 2,
    title: 'I shared my OTP, PIN or banking details',
    shortDesc: 'Shared an SMS OTP, UPI PIN, ATM PIN, CVV, NetBanking password, or card details.',
    urgencyLevel: 'CRITICAL - BLOCK CREDENTIALS IMMEDIATELY',
    questions: [
      {
        id: 'whatWasShared',
        question: 'Which details were shared?',
        options: ['Bank / UPI OTP or PIN', 'Debit / Credit Card Number & CVV', 'NetBanking Username / Password', 'Aadhaar / PAN / KYC Details']
      },
      {
        id: 'moneyDeducted',
        question: 'Has any money already been debited from your account?',
        options: ['Yes, money was deducted', 'Not yet / Unsure']
      }
    ],
    immediateSteps: [
      'BLOCK CARDS & FREEZE ACCOUNT IMMEDIATELY: Open your official banking app or call your bank\'s official 24x7 toll-free number to hotlist/block your Debit/Credit Card, disable UPI, and temporarily freeze outbound transfers.',
      'CHANGE COMPROMISED PASSWORDS & PINS: Using a trusted device and official bank portal, reset your NetBanking password, MPIN, and UPI PIN immediately.',
      'CHECK RECENT TRANSACTIONS & MANDATES: Inspect your bank statement and UPI AutoPay mandates for any unauthorized debits or newly added beneficiaries. If money was deducted, dial 1930 immediately.',
      'LOCK AADHAAR BIOMETRICS (IF KYC SHARED): If you shared Aadhaar OTP or details, lock your Aadhaar biometrics via the official mAadhaar app or https://myaadhaar.uidai.gov.in/.'
    ],
    doNotList: [
      'NEVER share another "cancellation OTP" with the caller—scammers often claim a second OTP is needed to cancel the first transaction.',
      'DO NOT click any link sent by the caller to "block" your account.'
    ]
  },
  {
    id: 'suspicious_link',
    number: 3,
    title: 'I clicked a suspicious website link',
    shortDesc: 'Opened an unknown link from SMS, WhatsApp, email, or social media.',
    urgencyLevel: 'HIGH - SECURE ACCOUNTS & DEVICE',
    questions: [
      {
        id: 'actionTakenOnLink',
        question: 'What happened after opening the link?',
        options: ['I only opened the page and closed it', 'I entered login, personal, or banking details', 'A file or app (.apk) started downloading']
      }
    ],
    immediateSteps: [
      'CLOSE THE TAB & DO NOT RE-OPEN: Immediately close the browser tab and clear recent browser site data/permissions for that website.',
      'IF YOU ENTERED PASSWORDS OR BANKING DETAILS: Immediately change the password for that account (and any other account using the same password) using the official app or website, and enable Two-Factor Authentication (2FA).',
      'IF YOU ENTERED CARD / UPI DETAILS: Contact your bank immediately to block the card or reset your UPI PIN, and monitor your account statement closely.',
      'CHECK DOWNLOADS FOLDER: Ensure no `.apk` or unknown file was downloaded and installed on your phone.'
    ],
    doNotList: [
      'DO NOT open the link again to "check" what it was.',
      'DO NOT allow browser notification or camera/microphone permissions requested by unfamiliar websites.'
    ]
  },
  {
    id: 'unknown_app',
    number: 4,
    title: 'I installed an unknown application',
    shortDesc: 'Installed an `.apk` file (e.g., fake bank/KYC/parivahan/electricity app) or unknown app.',
    urgencyLevel: 'CRITICAL - DISCONNECT NETWORK & REMOVE MALWARE',
    questions: [
      {
        id: 'appSource',
        question: 'How was the application installed?',
        options: ['Downloaded APK from WhatsApp / SMS link', 'Screen-sharing / Remote support app (AnyDesk, RustDesk, TeamViewer)', 'Unfamiliar app from store']
      },
      {
        id: 'permissionsGranted',
        question: 'Did you grant SMS, Accessibility, or Admin permissions?',
        options: ['Yes / Not sure', 'No, I did not open it']
      }
    ],
    immediateSteps: [
      'TURN ON AIRPLANE MODE IMMEDIATELY: Disable both Wi-Fi and Mobile Data right now. Malicious APK files forward your incoming bank SMS OTPs to scammers in real time; cutting off internet stops this immediately.',
      'REVOKE DEVICE ADMIN & ACCESSIBILITY PERMISSIONS: Go to Android Settings -> Security -> Device Admin Apps (and Settings -> Accessibility) and revoke permissions for any unfamiliar app so it allows uninstallation.',
      'UNINSTALL THE SUSPICIOUS APPLICATION: Go to Settings -> Apps, locate the newly installed app (note: some malicious APKs hide with blank names or bank icons), and tap Uninstall.',
      'SECURE ACCOUNTS FROM A DIFFERENT TRUSTED DEVICE: Using another safe phone or computer, change your banking passwords, check your bank balance, and call your bank / 1930 if any unauthorized transaction occurred.'
    ],
    doNotList: [
      'DO NOT log into your banking or UPI apps on the affected phone until the malicious app is completely removed and SMS forwarding permissions are audited.',
      'DO NOT keep Wi-Fi or Mobile Data on while searching for the malicious app.'
    ]
  },
  {
    id: 'remote_access',
    number: 5,
    title: 'Someone is controlling or accessing my phone',
    shortDesc: 'Screen sharing is active or someone can view your screen / OTPs remotely.',
    urgencyLevel: 'EMERGENCY - CUT CONNECTION IMMEDIATELY',
    questions: [
      {
        id: 'activeSession',
        question: 'Is the call or remote session still active right now?',
        options: ['Yes, happening right now', 'It ended recently']
      }
    ],
    immediateSteps: [
      'TURN ON AIRPLANE MODE / TURN OFF WIFI & DATA NOW: Immediately switch on Airplane Mode or power off the phone to sever the remote control connection.',
      'HANG UP ANY VOICE / WHATSAPP CALL: WhatsApp and Meet screen-sharing allows scammers to read your incoming OTP notifications directly off your screen.',
      'UNINSTALL REMOTE ACCESS APPS: Remove AnyDesk, TeamViewer, QuickSupport, RustDesk, AirDroid, or any screen-sharing tool you were instructed to install.',
      'CHECK CALL & SMS FORWARDING: Dial ##002# on your phone dialer to cancel all unconditional call forwardings, and inspect your SMS app permissions.',
      'CALL YOUR BANK & 1930: From another trusted phone, call your bank to verify no funds were transferred and dial 1930 immediately if any money is missing.'
    ],
    doNotList: [
      'DO NOT open your banking or UPI app while screen sharing or remote access software is installed.',
      'DO NOT follow any further instructions from the caller claiming to be from bank/KYC/customer support.'
    ]
  },
  {
    id: 'suspicious_call_msg',
    number: 6,
    title: 'I received a suspicious call or message',
    shortDesc: 'Fake police/customs "digital arrest" threat, KYC block alert, job offer, or lottery claim.',
    urgencyLevel: 'MODERATE - VERIFY & REPORT',
    questions: [
      {
        id: 'scamType',
        question: 'What did the caller or message claim?',
        options: [
          'Police / CBI / Customs / "Digital Arrest" threat',
          'Bank / KYC / Electricity / PAN block warning',
          'Part-time job / Task / Investment offer',
          'Friend/Relative in emergency asking for UPI money'
        ]
      }
    ],
    immediateSteps: [
      'DISCONNECT & DO NOT PANIC: Law enforcement agencies (Police, CBI, Customs, RBI, Courts) NEVER conduct interrogations or "digital arrests" over WhatsApp/Skype video calls and never demand money transfers to "verify" accounts.',
      'VERIFY INDEPENDENTLY: If a caller claims a family member is in trouble or a bank account is blocked, hang up and call your family member directly or check your official bank app.',
      'BLOCK & REPORT ON CHAKSHU (SANCHAR SAATHI): Report suspected fraud calls/SMS within 30 days on the Government of India Chakshu portal at https://sancharsaathi.gov.in/.',
      'SCAN THE MESSAGE OR LINK IN SCAMLENS: Paste the message text or website link into the ScamLens Scanner to inspect specific risk indicators.'
    ],
    doNotList: [
      'DO NOT stay on video/voice call with anyone threatening arrest or demanding secrecy.',
      'DO NOT transfer money to "safe government accounts" or pay registration fees for part-time tasks.'
    ]
  },
  {
    id: 'other_fraud',
    number: 7,
    title: 'Other digital fraud incidents',
    shortDesc: 'Social media account compromise, marketplace/OLX scam, SIM swap, or identity theft.',
    urgencyLevel: 'HIGH - SECURE ACCOUNTS & REPORT',
    questions: [
      {
        id: 'incidentNature',
        question: 'Which best describes the issue?',
        options: [
          'WhatsApp / Social Media account hacked',
          'Paid for an item online that was never delivered',
          'Sudden loss of mobile network (suspected SIM swap)',
          'Other cyber fraud'
        ]
      }
    ],
    immediateSteps: [
      'SECURE EMAIL & PRIMARY ACCOUNTS: Change the password on your primary email account first, revoke unknown logged-in devices, and enable Two-Step Verification (including WhatsApp Two-Step PIN).',
      'IF MOBILE SIGNAL SUDDENLY DROPPED (SIM SWAP): Contact your telecom operator and bank immediately using another phone—scammers use fraudulent SIM replacements to intercept bank OTPs.',
      'IF FINANCIAL LOSS OCCURRED: Immediately call the National Cybercrime Helpline at 1930 and file a complaint at https://cybercrime.gov.in/.',
      'WARN CONTACTS IF SOCIAL ACCOUNT COMPROMISED: Inform family and friends not to send money to messages coming from your compromised profile.'
    ],
    doNotList: [
      'DO NOT share 6-digit WhatsApp registration codes with anyone.',
      'DO NOT rely on unverified middlemen to recover hacked accounts.'
    ]
  }
];

function getAllGuidanceCategories() {
  return {
    questionPrompt: 'What happened to you?',
    categories: INCIDENT_CATEGORIES,
    officialResources: OFFICIAL_INDIAN_RESOURCES
  };
}

function getGuidanceForCategory(categoryId, selectedAnswers = {}) {
  const found = INCIDENT_CATEGORIES.find(c => c.id === categoryId) || INCIDENT_CATEGORIES[INCIDENT_CATEGORIES.length - 1];

  const tailoredSteps = [...found.immediateSteps];

  // Add context-specific priority advice based on selected answers
  if (selectedAnswers && typeof selectedAnswers === 'object') {
    if (selectedAnswers.timeElapsed === 'Within the last 1 hour') {
      tailoredSteps.unshift(
        'GOLDEN HOUR PRIORITY: Because this happened within the last hour, calling 1930 right now gives the highest probability of freezing the funds before the scammer transfers them out.'
      );
    }
    if (selectedAnswers.moneyDeducted === 'Yes, money was deducted' && found.id !== 'money_transfer') {
      tailoredSteps.unshift(
        'URGENT FINANCIAL LOSS: Since money has already been debited, immediately dial 1930 (National Cybercrime Helpline) to report the fraudulent debit and freeze the recipient account.'
      );
    }
    if (selectedAnswers.actionTakenOnLink === 'A file or app (.apk) started downloading') {
      tailoredSteps.unshift(
        'MALICIOUS APK WARNING: Do NOT open the downloaded APK file. Delete it from your Downloads folder immediately. If you already installed it, turn on Airplane Mode and uninstall it from Settings -> Apps.'
      );
    }
  }

  return {
    incidentCategory: found.id,
    incidentTitle: found.title,
    urgencyLevel: found.urgencyLevel,
    summary: found.shortDesc,
    immediateSteps: tailoredSteps,
    doNotList: found.doNotList,
    officialContacts: OFFICIAL_INDIAN_RESOURCES
  };
}

module.exports = {
  OFFICIAL_INDIAN_RESOURCES,
  INCIDENT_CATEGORIES,
  getAllGuidanceCategories,
  getGuidanceForCategory
};

