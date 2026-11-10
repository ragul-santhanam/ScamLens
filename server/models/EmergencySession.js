const mongoose = require('mongoose');
const { randomUUID } = require('crypto');

const EmergencySessionSchema = new mongoose.Schema(
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
    incidentCategory: {
      type: String,
      required: true,
      trim: true
    },
    incidentTitle: {
      type: String,
      required: true,
      trim: true
    },
    selectedAnswers: {
      type: mongoose.Schema.Types.Mixed,
      default: {}
    },
    guidanceProvided: {
      urgencyLevel: { type: String, default: 'CRITICAL' },
      summary: { type: String, default: '' },
      immediateSteps: [{ type: String }],
      doNotList: [{ type: String }],
      officialContacts: { type: mongoose.Schema.Types.Mixed, default: {} }
    },
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

let MongooseEmergencySession = null;
try {
  MongooseEmergencySession = mongoose.model('EmergencySession', EmergencySessionSchema);
} catch (e) {
  MongooseEmergencySession = mongoose.models.EmergencySession;
}

const inMemoryEmergencySessions = [];

class EmergencySessionService {
  static isDbConnected() {
    return mongoose.connection && mongoose.connection.readyState === 1;
  }

  static async create(data) {
    const validUserId = data.userId && mongoose.Types.ObjectId.isValid(data.userId) ? data.userId : null;
    const payload = {
      userId: validUserId,
      deviceId: data.deviceId || null,
      incidentCategory: data.incidentCategory,
      incidentTitle: data.incidentTitle || data.incidentCategory,
      selectedAnswers: data.selectedAnswers || {},
      guidanceProvided: data.guidanceProvided || {}
    };

    if (this.isDbConnected() && MongooseEmergencySession) {
      try {
        const doc = await MongooseEmergencySession.create(payload);
        return doc.toObject();
      } catch (err) {
        console.warn('[DB] EmergencySessionService.create fallback:', err.message);
      }
    }

    const mem = Object.assign({ _id: randomUUID(), createdAt: new Date() }, payload);
    inMemoryEmergencySessions.unshift(mem);
    return mem;
  }

  static async findByOwner({ userId, deviceId }, limit = 30) {
    if (this.isDbConnected() && MongooseEmergencySession) {
      try {
        const filter = userId && mongoose.Types.ObjectId.isValid(userId)
          ? { userId }
          : { deviceId };
        const docs = await MongooseEmergencySession.find(filter)
          .sort({ createdAt: -1 })
          .limit(limit)
          .lean();
        return docs;
      } catch (err) {
        console.warn('[DB] EmergencySessionService.findByOwner fallback:', err.message);
      }
    }

    return inMemoryEmergencySessions
      .filter(s => (userId ? String(s.userId) === String(userId) : s.deviceId === deviceId))
      .slice(0, limit);
  }
}

module.exports = {
  EmergencySession: MongooseEmergencySession,
  EmergencySessionSchema,
  EmergencySessionService
};

