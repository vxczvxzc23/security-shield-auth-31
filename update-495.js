const crypto = require('crypto');

/**
 * Hashes a plain text password using PBKDF2
 * @param {string} password 
 * @returns {string} salt:hash format
 */
const hashPassword = (password) => {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
  return `${salt}:${hash}`;
};

/**
 * Verifies a password against a stored hash string
 * @param {string} password 
 * @param {string} storedHash 
 * @returns {boolean}
 */
const verifyPassword = (password, storedHash) => {
  const [salt, hash] = storedHash.split(':');
  const checkHash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
  return hash === checkHash;
};

module.exports = { hashPassword, verifyPassword };