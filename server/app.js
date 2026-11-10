const path = require('path');
require('dotenv').config();
require('dotenv').config({ path: path.join(__dirname, '.env') });
require('dotenv').config({ path: path.join(__dirname, '../.env') });
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const mongoose = require('mongoose');
const os = require('os');

const healthRouter = require('./routes/health');
const authRouter = require('./routes/auth');
const analyzeRouter = require('./routes/analyze');
const historyRouter = require('./routes/history');
const paymentRouter = require('./routes/payment');
const qrRouter = require('./routes/qr');
const emergencyRouter = require('./routes/emergency');
const { errorHandler, notFoundHandler } = require('./middleware/errorHandler');

const app = express();
// Fixed to port 80 (the default web port) so URLs need no ":port". The PORT value in .env is ignored on purpose.
const PORT = 80;

// 1. Security Headers (Permit local HTTP LAN & localhost access without HSTS/COOP blocks)
app.use(
  helmet({
    contentSecurityPolicy: false,
    strictTransportSecurity: false,
    crossOriginOpenerPolicy: false,
    crossOriginResourcePolicy: false,
    originAgentCluster: false
  })
);

// Allow Chromium Private Network Access (e.g. localhost <-> 192.168.0.4 across Wi-Fi / WebView)
app.use((req, res, next) => {
  if (req.headers['access-control-request-private-network']) {
    res.setHeader('Access-Control-Allow-Private-Network', 'true');
  }
  next();
});

// 2. CORS Configuration
const allowedOrigins = [
  'https://localhost',
  'http://localhost',
  'capacitor://localhost',
  'http://127.0.0.1',
  'http://10.0.2.2',
  'http://192.168.0.4'
];

app.use(
  cors({
    origin: function (origin, callback) {
      // Allow mobile apps, curl, or matching origins
      if (!origin || allowedOrigins.includes(origin) || origin.startsWith('capacitor://') || origin.startsWith('http://localhost:')) {
        callback(null, true);
      } else {
        callback(null, true); // Permissive for local college testing while guarding headers
      }
    },
    methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
  })
);

// 3. Body Parser (Supports JSON & base64 screenshot payloads up to 6mb)
app.use(express.json({ limit: '6mb' }));

// 4. Privacy Guard: Disable request body logging
// DO NOT log req.body anywhere to protect user messages, credentials, and submitted links

// 5. API Routes
app.use('/api/health', healthRouter);
app.use('/api/auth', authRouter);
app.use('/api/analyze', analyzeRouter);
app.use('/api/history', historyRouter);
app.use('/api/payment', paymentRouter);
app.use('/api/qr', qrRouter);
app.use('/api/emergency', emergencyRouter);

// 6. Serve Mobile Web App frontend
const wwwPath = path.join(__dirname, '../app/www');
app.use(express.static(wwwPath));

// Explicit route for root and SPA navigation
app.get('/', (req, res) => {
  res.sendFile(path.join(wwwPath, 'index.html'));
});

// 7. Centralized Error Handling
app.use(notFoundHandler);
app.use(errorHandler);

// 7. Database Connection (Resilient: never crashes if Atlas is unreachable)
async function connectDatabase() {
  const mongoUri = process.env.MONGODB_URI;
  if (!mongoUri || mongoUri.includes('<username>')) {
    console.info('[DB] MONGODB_URI not set or contains placeholder. Operating with resilient in-memory fallback store.');
    return;
  }

  try {
    await mongoose.connect(mongoUri, {
      serverSelectionTimeoutMS: 5000,
      connectTimeoutMS: 5000
    });
    console.info('[DB] Successfully connected to MongoDB Atlas.');
  } catch (err) {
    console.warn('[DB] MongoDB Atlas connection failed:', err.message);
    console.info('[DB] Operating with resilient in-memory fallback store.');
  }
}

let serverInstance = null;
let mobileBridgeInstance = null;

function setupAdbUsbReverse(bridgePort) {
  try {
    const { execFile } = require('child_process');
    const localAppData = process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
    const adbPath = path.join(localAppData, 'Android', 'Sdk', 'platform-tools', 'adb.exe');
    execFile(adbPath, ['reverse', `tcp:${bridgePort}`, `tcp:${bridgePort}`], { timeout: 4000 }, (err) => {
      if (!err) {
        console.log(`[ScamLens Server] Android USB tunnel active (adb reverse tcp:${bridgePort} -> tcp:${bridgePort})`);
      }
    });
  } catch (e) {
    // Ignore if adb is not installed
  }
}

function freeOccupiedPort(targetPort) {
  try {
    const { execSync } = require('child_process');
    const out = execSync('netstat -ano -p tcp', { encoding: 'utf8', timeout: 3000 });
    const lines = out.split(/\r?\n/);
    const killedPids = new Set();
    for (const line of lines) {
      if (!/LISTENING/i.test(line)) continue;
      const parts = line.trim().split(/\s+/);
      if (parts.length < 5) continue;
      const localAddr = parts[1];
      const pid = parseInt(parts[parts.length - 1], 10);
      if (localAddr.endsWith(`:${targetPort}`) && pid && pid > 4 && pid !== process.pid && !killedPids.has(pid)) {
        try {
          process.kill(pid);
          killedPids.add(pid);
        } catch (e) {}
      }
    }
    return killedPids.size > 0;
  } catch (e) {
    return false;
  }
}

function startServer(port = PORT, isRetry = false) {
  return new Promise((resolve) => {
    if (!isRetry) connectDatabase();
    // 0.0.0.0 = listen on every network interface so the phone can reach it over Wi-Fi
    serverInstance = app.listen(port, '0.0.0.0', () => {
      const shown = Number(port) === 80 ? '' : `:${port}`;
      console.log(`[ScamLens Server] Running on http://localhost${shown}`);
      Object.values(os.networkInterfaces()).flat().forEach((i) => {
        if (i && i.family === 'IPv4' && !i.internal) {
          console.log(`[ScamLens Server] On your Wi-Fi (open on phone): http://${i.address}${shown}`);
        }
      });

      // When running as main server on port 80, also open port 3000 for Capacitor Android (USB adb reverse & Wi-Fi)
      if (require.main === module && Number(port) !== 3000) {
        const bridgePort = 3000;
        freeOccupiedPort(bridgePort);
        mobileBridgeInstance = app.listen(bridgePort, '0.0.0.0', () => {
          console.log(`[ScamLens Server] Mobile API Bridge listening on port ${bridgePort}`);
          setupAdbUsbReverse(bridgePort);
        });
        mobileBridgeInstance.on('error', () => {
          // Ignore if 3000 is already occupied
        });
      }

      resolve(serverInstance);
    });

    // Automatically replace stale ScamLens server instance if port is already taken
    serverInstance.on('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        if (!isRetry && freeOccupiedPort(port)) {
          console.log(`[ScamLens Server] Stopped previous server instance on port ${port}, restarting...`);
          setTimeout(() => {
            startServer(port, true).then(resolve);
          }, 500);
          return;
        }
        console.error(`\n[ScamLens Server] Port ${port} is already in use.`);
        console.error('  -> ScamLens is probably already running in another terminal. Use that one, or close it (Ctrl + C) and try again.');
        console.error(`  -> To find what is using the port: netstat -ano | findstr :${port}\n`);
        process.exit(1);
      }
      throw err;
    });
  });
}

function stopServer() {
  return new Promise((resolve) => {
    if (mobileBridgeInstance) {
      try { mobileBridgeInstance.close(); } catch (e) {}
      mobileBridgeInstance = null;
    }
    if (serverInstance) {
      serverInstance.close(() => {
        if (mongoose.connection && mongoose.connection.readyState !== 0) {
          mongoose.disconnect().finally(resolve);
        } else {
          resolve();
        }
      });
    } else {
      resolve();
    }
  });
}

if (require.main === module) {
  startServer(PORT);
}

module.exports = {
  app,
  startServer,
  stopServer
};