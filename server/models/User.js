const mongoose = require('mongoose');
const { randomUUID } = require('crypto');

const UserSchema = new mongoose.Schema(
  {
    fullName: {
      type: String,
      required: true,
      trim: true,
      maxlength: 100
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
      maxlength: 160
    },
    mobile: {
      type: String,
      default: '',
      trim: true,
      maxlength: 20
    },
    passwordHash: {
      type: String,
      required: true
    },
    acceptedTerms: {
      type: Boolean,
      default: true
    },
    resetCodeHash: {
      type: String,
      default: null
    },
    resetCodeExpiresAt: {
      type: Date,
      default: null
    },
    createdAt: {
      type: Date,
      default: Date.now
    }
  },
  {
    timestamps: false,
    versionKey: false
  }
);

let MongooseUserModel = null;
try {
  MongooseUserModel = mongoose.model('User', UserSchema);
} catch (e) {
  MongooseUserModel = mongoose.models.User;
}

const inMemoryUsers = [];

class UserService {
  static isDbConnected() {
    return mongoose.connection && mongoose.connection.readyState === 1;
  }

  static sanitizeUser(userDoc) {
    if (!userDoc) return null;
    return {
      id: (userDoc._id || userDoc.id).toString(),
      fullName: userDoc.fullName,
      email: userDoc.email,
      mobile: userDoc.mobile || '',
      createdAt: userDoc.createdAt
    };
  }

  static async findByEmail(email) {
    const normalizedEmail = String(email || '').trim().toLowerCase();
    if (!normalizedEmail) return null;

    if (this.isDbConnected() && MongooseUserModel) {
      try {
        const doc = await MongooseUserModel.findOne({ email: normalizedEmail }).lean();
        if (doc) return doc;
      } catch (err) {
        console.warn('[DB] UserService.findByEmail fallback:', err.message);
      }
    }

    return inMemoryUsers.find(u => u.email === normalizedEmail) || null;
  }

  static async findById(id) {
    if (!id) return null;
    const strId = id.toString();

    if (this.isDbConnected() && MongooseUserModel) {
      try {
        if (mongoose.Types.ObjectId.isValid(strId)) {
          const doc = await MongooseUserModel.findById(strId).lean();
          if (doc) return doc;
        }
      } catch (err) {
        console.warn('[DB] UserService.findById fallback:', err.message);
      }
    }

    return inMemoryUsers.find(u => u._id.toString() === strId) || null;
  }

  static async create({ fullName, email, mobile, passwordHash, acceptedTerms }) {
    const normalizedEmail = String(email || '').trim().toLowerCase();

    if (this.isDbConnected() && MongooseUserModel) {
      try {
        const doc = await MongooseUserModel.create({
          fullName: fullName.trim(),
          email: normalizedEmail,
          mobile: (mobile || '').trim(),
          passwordHash,
          acceptedTerms: Boolean(acceptedTerms)
        });
        return doc.toObject();
      } catch (err) {
        if (err.code === 11000) {
          const dupErr = new Error('An account with this email address already exists.');
          dupErr.status = 409;
          throw dupErr;
        }
        console.warn('[DB] UserService.create fallback to memory:', err.message);
      }
    }

    if (inMemoryUsers.some(u => u.email === normalizedEmail)) {
      const dupErr = new Error('An account with this email address already exists.');
      dupErr.status = 409;
      throw dupErr;
    }

    const record = {
      _id: new mongoose.Types.ObjectId().toString(),
      fullName: fullName.trim(),
      email: normalizedEmail,
      mobile: (mobile || '').trim(),
      passwordHash,
      acceptedTerms: Boolean(acceptedTerms),
      resetCodeHash: null,
      resetCodeExpiresAt: null,
      createdAt: new Date()
    };
    inMemoryUsers.push(record);
    return record;
  }

  static async updateResetCode(userId, resetCodeHash, resetCodeExpiresAt) {
    const strId = userId.toString();
    if (this.isDbConnected() && MongooseUserModel && mongoose.Types.ObjectId.isValid(strId)) {
      try {
        await MongooseUserModel.updateOne(
          { _id: strId },
          { $set: { resetCodeHash, resetCodeExpiresAt } }
        );
      } catch (err) {
        console.warn('[DB] UserService.updateResetCode fallback:', err.message);
      }
    }

    const memUser = inMemoryUsers.find(u => u._id.toString() === strId);
    if (memUser) {
      memUser.resetCodeHash = resetCodeHash;
      memUser.resetCodeExpiresAt = resetCodeExpiresAt;
    }
  }

  static async updatePassword(userId, newPasswordHash) {
    const strId = userId.toString();
    if (this.isDbConnected() && MongooseUserModel && mongoose.Types.ObjectId.isValid(strId)) {
      try {
        await MongooseUserModel.updateOne(
          { _id: strId },
          { $set: { passwordHash: newPasswordHash, resetCodeHash: null, resetCodeExpiresAt: null } }
        );
      } catch (err) {
        console.warn('[DB] UserService.updatePassword fallback:', err.message);
      }
    }

    const memUser = inMemoryUsers.find(u => u._id.toString() === strId);
    if (memUser) {
      memUser.passwordHash = newPasswordHash;
      memUser.resetCodeHash = null;
      memUser.resetCodeExpiresAt = null;
    }
  }
}

module.exports = {
  User: MongooseUserModel,
  UserSchema,
  UserService
};

