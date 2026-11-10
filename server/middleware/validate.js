const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Validate UUID format
 */
function isValidUuid(id) {
  return typeof id === 'string' && UUID_REGEX.test(id.trim());
}

/**
 * Middleware: Validate deviceId in query string (or allow authenticated user)
 */
function validateDeviceQuery(req, res, next) {
  const deviceId = req.query.deviceId;
  if (deviceId !== undefined) {
    if (!deviceId || !isValidUuid(deviceId)) {
      return res.status(400).json({
        error: 'Invalid or missing deviceId. Must be a valid UUID v4.'
      });
    }
    req.validatedDeviceId = deviceId.trim();
    return next();
  }

  if (req.user && req.user.id) {
    req.validatedDeviceId = null;
    return next();
  }

  return res.status(400).json({
    error: 'Invalid or missing deviceId. Must be a valid UUID v4.'
  });
}

/**
 * Middleware: Validate analyze message payload
 */
function validateMessagePayload(req, res, next) {
  const { text, deviceId } = req.body || {};

  if (deviceId !== undefined || !req.user) {
    if (!deviceId || !isValidUuid(deviceId)) {
      return res.status(400).json({
        error: 'Invalid or missing deviceId. Must be a valid UUID v4.'
      });
    }
    req.validatedDeviceId = deviceId.trim();
  } else {
    req.validatedDeviceId = 'authenticated-user-device';
  }

  if (typeof text !== 'string' || !text.trim()) {
    return res.status(400).json({
      error: 'Text field is required and must not be empty.'
    });
  }

  if (text.length > 2000) {
    return res.status(400).json({
      error: 'Text exceeds maximum length of 2000 characters.'
    });
  }

  req.validatedText = text;
  next();
}

/**
 * Middleware: Validate analyze URL payload
 */
function validateUrlPayload(req, res, next) {
  const { url, deviceId } = req.body || {};

  if (deviceId !== undefined || !req.user) {
    if (!deviceId || !isValidUuid(deviceId)) {
      return res.status(400).json({
        error: 'Invalid or missing deviceId. Must be a valid UUID v4.'
      });
    }
    req.validatedDeviceId = deviceId.trim();
  } else {
    req.validatedDeviceId = 'authenticated-user-device';
  }

  if (typeof url !== 'string' || !url.trim()) {
    return res.status(400).json({
      error: 'URL field is required and must not be empty.'
    });
  }

  if (url.length > 2048) {
    return res.status(400).json({
      error: 'URL exceeds maximum length of 2048 characters.'
    });
  }

  // Basic URL syntax check
  const trimmedUrl = url.trim();
  try {
    const testUrl = /^https?:\/\//i.test(trimmedUrl) ? trimmedUrl : `http://${trimmedUrl}`;
    const parsed = new URL(testUrl);
    if (!parsed.hostname || !parsed.hostname.includes('.')) {
      return res.status(400).json({
        error: 'Invalid URL format provided. Must include a valid domain.'
      });
    }
  } catch (err) {
    return res.status(400).json({
      error: 'Invalid URL format provided.'
    });
  }

  req.validatedUrl = trimmedUrl;
  next();
}

module.exports = {
  isValidUuid,
  validateDeviceQuery,
  validateMessagePayload,
  validateUrlPayload
};
