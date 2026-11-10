const mongoose = require('mongoose');
const { randomUUID } = require('crypto');

const QRScanSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      index: true,
      default: null
    },
    deviceId: {
      type: String,
      index: true,
      default: null
    },
    scanCategory: {
      type: String,
      default: 'qr'
    },
    contentType: {
      type: String,
      enum: ['url', 'upi', 'text', 'other'],
      required: true
    },
    maskedPreview: {
      type: String,
      required: true,
      maxlength: 60,
      trim: true
    },
    extractedUrl: {
      type: String,
      default: null
    },
    qrDetails: {
      type: mongoose.Schema.Types.Mixed,
      default: {}
    },
    riskLevel: {
      type: String,
      enum: ['Low Risk', 'Suspicious', 'High Risk'],
      required: true
    },
    riskCategory: {
      type: String,
      default: 'Low Risk Indicators'
    },
    score: {
      type: Number,
      required: true,
      min: 0,
      max: 100
    },
    firedRules: [
      {
        id: { type: String, required: true },
        title: { type: String, required: true },
        explanation: { type: String, required: true }
      }
    ],
    actions: [{ type: String }],
    createdAt: {
      type: Date,
      default: Date.now,
      expires: 7776000
    }
  },
  {
    timestamps: false,
    versionKey: false
  }
);

let MongooseQRScan = null;
try {
  MongooseQRScan = mongoose.model('QRScan', QRScanSchema);
} catch (e) {
  MongooseQRScan = mongoose.models.QRScan;
}

const inMemoryQRScans = [];

class QRScanService {
  static isDbConnected() {
    return mongoose.connection && mongoose.connection.readyState === 1;
  }

  static async create(data) {
    const validUserId = data.userId && mongoose.Types.ObjectId.isValid(data.userId) ? data.userId : null;
    const payload = {
      userId: validUserId,
      deviceId: data.deviceId || null,
      scanCategory: 'qr',
      contentType: data.contentType || 'text',
      maskedPreview: (data.maskedPreview || 'QR Code Scan').slice(0, 60),
      extractedUrl: data.extractedUrl || null,
      qrDetails: data.qrDetails || {},
      riskLevel: data.riskLevel,
      riskCategory: data.riskCategory || 'Low Risk Indicators',
      score: data.score,
      firedRules: Array.isArray(data.firedRules) ? data.firedRules : [],
      actions: Array.isArray(data.actions) ? data.actions : []
    };

    if (this.isDbConnected() && MongooseQRScan) {
      try {
        const doc = await MongooseQRScan.create(payload);
        return doc.toObject();
      } catch (err) {
        console.warn('[DB] QRScanService.create fallback:', err.message);
      }
    }

    const mem = Object.assign({ _id: randomUUID(), createdAt: new Date() }, payload);
    inMemoryQRScans.unshift(mem);
    return mem;
  }

  static async findByOwner({ userId, deviceId }, limit = 50) {
    if (this.isDbConnected() && MongooseQRScan) {
      try {
        const filter = userId && mongoose.Types.ObjectId.isValid(userId)
          ? { userId }
          : { deviceId };
        const docs = await MongooseQRScan.find(filter)
          .sort({ createdAt: -1 })
          .limit(limit)
          .lean();
        return docs;
      } catch (err) {
        console.warn('[DB] QRScanService.findByOwner fallback:', err.message);
      }
    }

    return inMemoryQRScans
      .filter(s => (userId ? String(s.userId) === String(userId) : s.deviceId === deviceId))
      .slice(0, limit);
  }
}

module.exports = {
  QRScan: MongooseQRScan,
  QRScanSchema,
  QRScanService
};

