const {
  getAllGuidanceCategories,
  getGuidanceForCategory,
  INCIDENT_CATEGORIES
} = require('../services/emergencyGuidanceService');
const { EmergencySessionService } = require('../models/EmergencySession');

/**
 * GET /api/emergency/guidance
 */
async function getGuidance(req, res, next) {
  try {
    const categoryId = req.query.category;
    if (categoryId) {
      const valid = INCIDENT_CATEGORIES.some(c => c.id === categoryId);
      if (!valid) {
        return res.status(400).json({ error: 'Invalid emergency incident category.' });
      }
      const guidance = getGuidanceForCategory(categoryId, {});
      return res.json(guidance);
    }

    res.json(getAllGuidanceCategories());
  } catch (err) {
    next(err);
  }
}

/**
 * POST /api/emergency/session
 */
async function saveEmergencySession(req, res, next) {
  try {
    const { incidentCategory, selectedAnswers, deviceId } = req.body || {};
    const userId = req.user ? req.user.id : null;

    if (!incidentCategory || typeof incidentCategory !== 'string') {
      return res.status(400).json({ error: 'Incident category is required.' });
    }

    const validCategory = INCIDENT_CATEGORIES.find(c => c.id === incidentCategory.trim());
    if (!validCategory) {
      return res.status(400).json({ error: 'Unrecognized incident category.' });
    }

    const sanitizedAnswers = {};
    if (selectedAnswers && typeof selectedAnswers === 'object' && !Array.isArray(selectedAnswers)) {
      Object.keys(selectedAnswers).slice(0, 10).forEach(k => {
        const val = selectedAnswers[k];
        if (typeof val === 'string') {
          sanitizedAnswers[k] = val.trim().slice(0, 200);
        }
      });
    }

    const guidance = getGuidanceForCategory(validCategory.id, sanitizedAnswers);

    const saved = await EmergencySessionService.create({
      userId,
      deviceId: deviceId || 'authenticated-user-device',
      incidentCategory: validCategory.id,
      incidentTitle: validCategory.title,
      selectedAnswers: sanitizedAnswers,
      guidanceProvided: {
        urgencyLevel: guidance.urgencyLevel,
        summary: guidance.summary,
        immediateSteps: guidance.immediateSteps,
        doNotList: guidance.doNotList,
        officialContacts: guidance.officialContacts
      }
    });

    res.status(201).json({
      sessionId: saved ? saved._id : null,
      incidentCategory: validCategory.id,
      incidentTitle: validCategory.title,
      selectedAnswers: sanitizedAnswers,
      guidanceProvided: guidance,
      createdAt: saved ? saved.createdAt : new Date().toISOString()
    });
  } catch (err) {
    next(err);
  }
}

/**
 * GET /api/emergency/history
 */
async function getEmergencyHistory(req, res, next) {
  try {
    const userId = req.user ? req.user.id : null;
    const deviceId = req.query.deviceId || null;

    if (!userId && !deviceId) {
      return res.status(401).json({ error: 'Authentication or deviceId required to view assistance history.' });
    }

    const sessions = await EmergencySessionService.findByOwner({ userId, deviceId }, 30);
    res.json(sessions);
  } catch (err) {
    next(err);
  }
}

module.exports = {
  getGuidance,
  saveEmergencySession,
  getEmergencyHistory
};

