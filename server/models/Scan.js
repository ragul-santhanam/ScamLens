const mongoose = require('mongoose');
const { randomUUID } = require('crypto');

// Mongoose Schema Definition
const ScanSchema = new mongoose.Schema(
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
      trim: true,
      default: 'authenticated-user-device'
    },
    type: {
      type: String,
      enum: ['message', 'url', 'qr', 'payment'],
      required: true
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
    maskedPreview: {
      type: String,
      required: true,
      maxlength: 60,
      trim: true
    },
    details: {
      type: mongoose.Schema.Types.Mixed,
      default: null
    },
    createdAt: {
      type: Date,
      default: Date.now,
      expires: 7776000 // 90-day TTL index (in seconds)
    }
  },
  {
    timestamps: false,
    versionKey: false
  }
);

// Primary Mongoose Model
let MongooseScanModel = null;
try {
  MongooseScanModel = mongoose.model('Scan', ScanSchema);
} catch (e) {
  MongooseScanModel = mongoose.models.Scan;
}

// In-Memory Fallback Storage (Used when MongoDB is unreachable or unconfigured)
const inMemoryStore = [];

/**
 * Universal Data Access Object:
 * Automatically uses MongoDB Atlas if mongoose.connection.readyState === 1.
 * Otherwise uses In-Memory fallback store with identical contract.
 */
class ScanService {
  static isDbConnected() {
    return mongoose.connection && mongoose.connection.readyState === 1;
  }

  static async create(data) {
    const validUserId = data.userId && mongoose.Types.ObjectId.isValid(data.userId)
      ? data.userId
      : null;

    const payload = {
      userId: validUserId,
      deviceId: data.deviceId || 'authenticated-user-device',
      type: data.type,
      riskLevel: data.riskLevel,
      riskCategory: data.riskCategory || (
        data.riskLevel === 'High Risk' ? 'High Risk Indicators' :
        data.riskLevel === 'Suspicious' ? 'Medium Risk Indicators' :
        'Low Risk Indicators'
      ),
      score: data.score,
      firedRules: Array.isArray(data.firedRules) ? data.firedRules : [],
      maskedPreview: (data.maskedPreview || 'Scan').slice(0, 60),
      details: data.details || null
    };

    if (this.isDbConnected() && MongooseScanModel) {
      try {
        const doc = await MongooseScanModel.create(payload);
        return doc.toObject();
      } catch (err) {
        // Fallback silently without crashing as required by spec
        console.warn('[DB] MongoDB create failed, falling back to memory:', err.message);
      }
    }

    // In-memory fallback
    const memoryRecord = Object.assign(
      {
        _id: randomUUID(),
        createdAt: new Date()
      },
      payload,
      { userId: data.userId ? data.userId.toString() : null }
    );
    inMemoryStore.unshift(memoryRecord);
    return memoryRecord;
  }

  static async findByDevice(deviceId, limit = 50) {
    if (this.isDbConnected() && MongooseScanModel) {
      try {
        const docs = await MongooseScanModel.find({ deviceId })
          .sort({ createdAt: -1 })
          .limit(limit)
          .lean();
        return docs;
      } catch (err) {
        console.warn('[DB] MongoDB findByDevice failed, using memory fallback:', err.message);
      }
    }

    // Filter by deviceId strictly
    return inMemoryStore
      .filter(item => item.deviceId === deviceId)
      .slice(0, limit);
  }

  static async findByOwner({ userId, deviceId }, limit = 50) {
    if (userId) {
      const strUserId = userId.toString();
      if (this.isDbConnected() && MongooseScanModel && mongoose.Types.ObjectId.isValid(strUserId)) {
        try {
          const docs = await MongooseScanModel.find({ userId: strUserId })
            .sort({ createdAt: -1 })
            .limit(limit)
            .lean();
          return docs;
        } catch (err) {
          console.warn('[DB] MongoDB findByOwner failed, using memory fallback:', err.message);
        }
      }
      return inMemoryStore
        .filter(item => item.userId && item.userId.toString() === strUserId)
        .slice(0, limit);
    }
    return this.findByDevice(deviceId, limit);
  }

  static async countByUser(userId) {
    if (!userId) return 0;
    const strUserId = userId.toString();
    if (this.isDbConnected() && MongooseScanModel && mongoose.Types.ObjectId.isValid(strUserId)) {
      try {
        return await MongooseScanModel.countDocuments({ userId: strUserId });
      } catch (err) {
        console.warn('[DB] MongoDB countByUser failed:', err.message);
      }
    }
    return inMemoryStore.filter(item => item.userId && item.userId.toString() === strUserId).length;
  }

  static async findByIdAndDevice(id, deviceId) {
    if (this.isDbConnected() && MongooseScanModel) {
      try {
        if (mongoose.Types.ObjectId.isValid(id)) {
          const doc = await MongooseScanModel.findOne({ _id: id, deviceId }).lean();
          if (doc) return doc;
        }
      } catch (err) {
        console.warn('[DB] MongoDB findById failed, checking memory:', err.message);
      }
    }

    return inMemoryStore.find(item => item._id.toString() === id.toString() && item.deviceId === deviceId) || null;
  }

  static async findByIdAndOwner(id, { userId, deviceId }) {
    if (userId) {
      const strUserId = userId.toString();
      if (this.isDbConnected() && MongooseScanModel && mongoose.Types.ObjectId.isValid(id) && mongoose.Types.ObjectId.isValid(strUserId)) {
        try {
          const doc = await MongooseScanModel.findOne({ _id: id, userId: strUserId }).lean();
          if (doc) return doc;
        } catch (err) {
          console.warn('[DB] MongoDB findByIdAndOwner failed:', err.message);
        }
      }
      const found = inMemoryStore.find(
        item => item._id.toString() === id.toString() && item.userId && item.userId.toString() === strUserId
      );
      if (found) return found;
    }
    if (deviceId) {
      return this.findByIdAndDevice(id, deviceId);
    }
    return null;
  }

  static async deleteByIdAndDevice(id, deviceId) {
    if (this.isDbConnected() && MongooseScanModel) {
      try {
        if (mongoose.Types.ObjectId.isValid(id)) {
          const res = await MongooseScanModel.deleteOne({ _id: id, deviceId });
          if (res.deletedCount > 0) return true;
        }
      } catch (err) {
        console.warn('[DB] MongoDB deleteById failed:', err.message);
      }
    }

    const index = inMemoryStore.findIndex(
      item => item._id.toString() === id.toString() && item.deviceId === deviceId
    );
    if (index !== -1) {
      inMemoryStore.splice(index, 1);
      return true;
    }
    return false;
  }

  static async deleteByIdAndOwner(id, { userId, deviceId }) {
    if (userId) {
      const strUserId = userId.toString();
      if (this.isDbConnected() && MongooseScanModel && mongoose.Types.ObjectId.isValid(id) && mongoose.Types.ObjectId.isValid(strUserId)) {
        try {
          const res = await MongooseScanModel.deleteOne({ _id: id, userId: strUserId });
          if (res.deletedCount > 0) return true;
        } catch (err) {
          console.warn('[DB] MongoDB deleteByIdAndOwner failed:', err.message);
        }
      }
      const idx = inMemoryStore.findIndex(
        item => item._id.toString() === id.toString() && item.userId && item.userId.toString() === strUserId
      );
      if (idx !== -1) {
        inMemoryStore.splice(idx, 1);
        return true;
      }
    }
    if (deviceId) {
      return this.deleteByIdAndDevice(id, deviceId);
    }
    return false;
  }

  static async clearAllByDevice(deviceId) {
    let deletedCount = 0;
    if (this.isDbConnected() && MongooseScanModel) {
      try {
        const res = await MongooseScanModel.deleteMany({ deviceId });
        deletedCount = res.deletedCount || 0;
      } catch (err) {
        console.warn('[DB] MongoDB clearAll failed:', err.message);
      }
    }

    // Clear memory store as well
    for (let i = inMemoryStore.length - 1; i >= 0; i--) {
      if (inMemoryStore[i].deviceId === deviceId) {
        inMemoryStore.splice(i, 1);
        deletedCount++;
      }
    }

    return deletedCount;
  }

  static async clearAllByOwner({ userId, deviceId }) {
    if (userId) {
      let deletedCount = 0;
      const strUserId = userId.toString();
      if (this.isDbConnected() && MongooseScanModel && mongoose.Types.ObjectId.isValid(strUserId)) {
        try {
          const res = await MongooseScanModel.deleteMany({ userId: strUserId });
          deletedCount = res.deletedCount || 0;
        } catch (err) {
          console.warn('[DB] MongoDB clearAllByOwner failed:', err.message);
        }
      }
      for (let i = inMemoryStore.length - 1; i >= 0; i--) {
        if (inMemoryStore[i].userId && inMemoryStore[i].userId.toString() === strUserId) {
          inMemoryStore.splice(i, 1);
          deletedCount++;
        }
      }
      return deletedCount;
    }
    if (deviceId) {
      return this.clearAllByDevice(deviceId);
    }
    return 0;
  }
}

module.exports = {
  Scan: MongooseScanModel,
  ScanSchema,
  ScanService
};
