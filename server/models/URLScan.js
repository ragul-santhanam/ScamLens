const mongoose = require('mongoose');
const { randomUUID } = require('crypto');

const URLScanSchema = new mongoose.Schema(
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
      default: 'url'
    },
    maskedPreview: {
      type: String,
      required: true,
      maxlength: 60,
      trim: true
    },
    normalizedDomain: {
      type: String,
      default: '',
      trim: true
    },
    identityReport: {
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

let MongooseURLScan = null;
try {
  MongooseURLScan = mongoose.model('URLScan', URLScanSchema);
} catch (e) {
  MongooseURLScan = mongoose.models.URLScan;
}

const inMemoryURLScans = [];

class URLScanService {
  static isDbConnected() {
    return mongoose.connection && mongoose.connection.readyState === 1;
  }

  static async create(data) {
    const validUserId = data.userId && mongoose.Types.ObjectId.isValid(data.userId) ? data.userId : null;
    const payload = {
      userId: validUserId,
      deviceId: data.deviceId || null,
      scanCategory: 'url',
      maskedPreview: (data.maskedPreview || '').slice(0, 60),
      normalizedDomain: data.normalizedDomain || '',
      identityReport: data.identityReport || {},
      riskLevel: data.riskLevel,
      riskCategory: data.riskCategory || 'Low Risk Indicators',
      score: data.score,
      firedRules: Array.isArray(data.firedRules) ? data.firedRules : [],
      actions: Array.isArray(data.actions) ? data.actions : []
    };

    if (this.isDbConnected() && MongooseURLScan) {
      try {
        const doc = await MongooseURLScan.create(payload);
        return doc.toObject();
      } catch (err) {
        console.warn('[DB] URLScanService.create fallback:', err.message);
      }
    }

    const mem = Object.assign({ _id: randomUUID(), createdAt: new Date() }, payload);
    inMemoryURLScans.unshift(mem);
    return mem;
  }
}

module.exports = {
  URLScan: MongooseURLScan,
  URLScanSchema,
  URLScanService
};

