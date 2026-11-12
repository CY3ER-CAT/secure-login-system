'use strict';

const { body, validationResult } = require('express-validator');
const { validatePasswordStrength } = require('../utils/password');

const RESERVED_USERNAMES = new Set([
  'admin', 'administrator', 'root', 'system', 'support', 'security',
  'help', 'api', 'login', 'logout', 'register', 'signup', 'dashboard',
  'twofactor', 'two-factor', 'account', 'settings', 'null', 'undefined'
]);

function collapseWhitespace(value) {
  return String(value ?? '').trim().replace(/\s+/g, ' ');
}

const registerValidation = [
  body('full_name')
    .customSanitizer(collapseWhitespace)
    .isLength({ min: 2, max: 80 })
    .withMessage('Full name must be between 2 and 80 characters.')
    .matches(/^[\p{L}\p{M}' .-]+$/u)
    .withMessage('Full name may only contain letters, spaces, apostrophes, periods and hyphens.'),

  body('email')
    .customSanitizer((value) => String(value ?? '').trim().toLowerCase())
    .isLength({ min: 3, max: 254 })
    .withMessage('Email address is too long.')
    .isEmail({ allow_utf8_local_part: false, require_tld: true })
    .withMessage('Enter a valid email address.'),

  body('username')
    .customSanitizer((value) => String(value ?? '').trim().toLowerCase())
    .isLength({ min: 3, max: 30 })
    .withMessage('Username must be between 3 and 30 characters.')
    .matches(/^[a-z0-9_]+$/)
    .withMessage('Username may only contain letters, numbers and underscores.')
    .custom((value) => {
      if (RESERVED_USERNAMES.has(value)) {
        throw new Error('That username is not available.');
      }
      return true;
    }),

  body('password')
    .isString()
    .withMessage('Password is required.')
    .custom((value, { req }) => {
      const result = validatePasswordStrength(value, {
        username: req.body.username,
        email: req.body.email
      });
      if (!result.valid) {
        throw new Error(result.errors[0]);
      }
      return true;
    }),

  body('confirm_password')
    .isString()
    .withMessage('Please confirm your password.')
    .custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Passwords do not match.');
      }
      return true;
    })
];

const loginValidation = [
  body('identifier')
    .customSanitizer((value) => String(value ?? '').trim())
    .isLength({ min: 3, max: 254 })
    .withMessage('Enter your username or email address.'),
  body('password')
    .isString()
    .withMessage('Password is required.')
    .isLength({ min: 1, max: 200 })
    .withMessage('Password is required.')
];

const twoFactorCodeValidation = [
  body('code')
    .customSanitizer((value) => String(value ?? '').trim())
    .isLength({ min: 6, max: 20 })
    .withMessage('Enter the 6-digit code or a recovery code.')
];

const setupCodeValidation = [
  body('code')
    .customSanitizer((value) => String(value ?? '').trim())
    .matches(/^\d{6}$/)
    .withMessage('Enter the 6-digit code from your authenticator app.')
];

const passwordStepUpValidation = [
  body('password')
    .isString()
    .withMessage('Password is required.')
    .isLength({ min: 1, max: 200 })
    .withMessage('Password is required.')
];

const disableTwoFactorValidation = [
  ...passwordStepUpValidation,
  ...twoFactorCodeValidation
];

function handleValidationErrors(req, res, next) {
  const result = validationResult(req);
  if (result.isEmpty()) return next();

  const errors = {};
  for (const error of result.array()) {
    if (!errors[error.path]) {
      errors[error.path] = error.msg;
    }
  }

  return res.status(422).json({
    code: 'VALIDATION_ERROR',
    message: 'Please correct the highlighted fields.',
    errors
  });
}

module.exports = {
  registerValidation,
  loginValidation,
  twoFactorCodeValidation,
  setupCodeValidation,
  passwordStepUpValidation,
  disableTwoFactorValidation,
  handleValidationErrors
};
