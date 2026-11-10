/**
 * Centralized Error Handler
 * Ensures no stack traces or sensitive internals leak in production or development responses.
 */
function errorHandler(err, req, res, next) {
  // Silent log of error name/message for diagnostics, omitting request body/personal data
  console.error(`[Error] ${req.method} ${req.path} -> ${err.name || 'Error'}: ${err.message}`);

  const statusCode = err.status || err.statusCode || 500;
  const message = statusCode >= 500 
    ? 'An unexpected internal error occurred. Please try again later.'
    : err.message || 'Request could not be processed.';

  res.status(statusCode).json({
    error: message
  });
}

/**
 * 404 Route Handler
 */
function notFoundHandler(req, res) {
  res.status(404).json({
    error: `Route not found: ${req.method} ${req.originalUrl}`
  });
}

module.exports = {
  errorHandler,
  notFoundHandler
};

