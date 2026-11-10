const mongoose = require('mongoose');
const { randomUUID } = require('crypto');

const MessageScanSchema = new mongoose.Schema(
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
      default: 'message'
    },
    maskedPreview: {
      type: String,
      required: true,
      maxlength: 60,
      trim: true
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

let MongooseMessageScan = null;
try {
  MongooseMessageScan = mongoose.model('MessageScan', MessageScanSchema);
} catch (e) {
  MongooseMessageScan = mongoose.models.MessageScan;
}

const inMemoryMessageScans = [];

class MessageScanService {
  static isDbConnected() {
    return mongoose.connection && mongoose.connection.readyState === 1;
  }

  static async create(data) {
    const validUserId = data.userId && mongoose.Types.ObjectId.isValid(data.userId) ? data.userId : null;
    const payload = {
      userId: validUserId,
      deviceId: data.deviceId || null,
      scanCategory: 'message',
      maskedPreview: (data.maskedPreview || '').slice(0, 60),
      riskLevel: data.riskLevel,
      riskCategory: data.riskCategory || 'Low Risk Indicators',
      score: data.score,
      firedRules: Array.isArray(data.firedRules) ? data.firedRules : [],
      actions: Array.isArray(data.actions) ? data.actions : []
    };

    if (this.isDbConnected() && MongooseMessageScan) {
      try {
        const doc = await MongooseMessageScan.create(payload);
        return doc.toObject();
      } catch (err) {
        console.warn('[DB] MessageScanService.create fallback:', err.message);
      }
    }

    const mem = Object.assign({ _id: randomUUID(), createdAt: new Date() }, payload);
    inMemoryMessageScans.unshift(mem);
    return mem;
  }
}

module.exports = {
  MessageScan: MongooseMessageScan,
  MessageScanSchema,
  MessageScanService
};

