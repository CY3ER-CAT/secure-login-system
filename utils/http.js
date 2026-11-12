'use strict';

function nowIso() {
  return new Date().toISOString();
}

function asyncHandler(handler) {
  return function wrapped(req, res, next) {
    Promise.resolve(handler(req, res, next)).catch(next);
  };
}

module.exports = { nowIso, asyncHandler };
