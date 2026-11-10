const mongoose = require('mongoose');
const { randomUUID } = require('crypto');

const PaymentScreenshotScanSchema = new mongoose.Schema(
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
      default: 'payment'
    },
    utrNumber: {
      type: String,
      index: true,
      default: null
    },
    maskedPreview: {
      type: String,
      required: true,
      maxlength: 60,
      trim: true
    },
    extractedInfo: {
      transactionId: { type: String, default: null },
      amount: { type: String, default: null },
      dateTime: { type: String, default: null },
      senderReceiver: { type: String, default: null },
      paymentStatus: { type: String, default: null },
      appDetected: { type: String, default: null }
    },
    imageMeta: {
      mimeType: { type: String, default: '' },
      sizeBytes: { type: Number, default: 0 },
      width: { type: Number, default: 0 },
      height: { type: Number, default: 0 }
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

let MongoosePaymentScan = null;
try {
  MongoosePaymentScan = mongoose.model('PaymentScreenshotScan', PaymentScreenshotScanSchema);
} catch (e) {
  MongoosePaymentScan = mongoose.models.PaymentScreenshotScan;
}

const inMemoryPaymentScans = [];

class PaymentScreenshotScanService {
  static isDbConnected() {
    return mongoose.connection && mongoose.connection.readyState === 1;
  }

  static async findByUtr(utrNumber) {
    if (!utrNumber) return null;
    const cleanUtr = String(utrNumber).trim();
    if (!cleanUtr) return null;

    if (this.isDbConnected() && MongoosePaymentScan) {
      try {
        const doc = await MongoosePaymentScan.findOne({ utrNumber: cleanUtr }).lean();
        if (doc) return doc;
      } catch (err) {
        console.warn('[DB] PaymentScreenshotScanService.findByUtr fallback:', err.message);
      }
    }

    return inMemoryPaymentScans.find(s => s.utrNumber === cleanUtr) || null;
  }

  static async create(data) {
    const validUserId = data.userId && mongoose.Types.ObjectId.isValid(data.userId) ? data.userId : null;
    const payload = {
      userId: validUserId,
      deviceId: data.deviceId || null,
      scanCategory: 'payment',
      utrNumber: data.utrNumber || null,
      maskedPreview: (data.maskedPreview || 'Payment Screenshot Scan').slice(0, 60),
      extractedInfo: data.extractedInfo || {},
      imageMeta: data.imageMeta || {},
      riskLevel: data.riskLevel,
      riskCategory: data.riskCategory || 'Low Risk Indicators',
      score: data.score,
      firedRules: Array.isArray(data.firedRules) ? data.firedRules : [],
      actions: Array.isArray(data.actions) ? data.actions : []
    };

    if (this.isDbConnected() && MongoosePaymentScan) {
      try {
        const doc = await MongoosePaymentScan.create(payload);
        return doc.toObject();
      } catch (err) {
        console.warn('[DB] PaymentScreenshotScanService.create fallback:', err.message);
      }
    }

    const mem = Object.assign({ _id: randomUUID(), createdAt: new Date() }, payload);
    inMemoryPaymentScans.unshift(mem);
    return mem;
  }

  static async findByOwner({ userId, deviceId }, limit = 50) {
    if (this.isDbConnected() && MongoosePaymentScan) {
      try {
        const filter = userId && mongoose.Types.ObjectId.isValid(userId)
          ? { userId }
          : { deviceId };
        const docs = await MongoosePaymentScan.find(filter)
          .sort({ createdAt: -1 })
          .limit(limit)
          .lean();
        return docs;
      } catch (err) {
        console.warn('[DB] PaymentScreenshotScanService.findByOwner fallback:', err.message);
      }
    }

    return inMemoryPaymentScans
      .filter(s => (userId ? String(s.userId) === String(userId) : s.deviceId === deviceId))
      .slice(0, limit);
  }
}

module.exports = {
  PaymentScreenshotScan: MongoosePaymentScan,
  PaymentScreenshotScanSchema,
  PaymentScreenshotScanService
};

