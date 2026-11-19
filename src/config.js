const fs = require('fs');
const path = require('path');

function exampleValues() {
  const file = path.join(__dirname, '..', '.env.example');
  return new Set(fs.readFileSync(file, 'utf8').split(/\r?\n/)
    .map((line) => line.match(/^\s*[^#=\s]+\s*=(.*)$/)?.[1]?.replace(/\s+#.*$/, '').trim())
    .filter(Boolean));
}

function validateProductionEnv(env = process.env) {
  const names = ['USER_JWT_SECRET', 'ADMIN_JWT_SECRET', 'ENTITLEMENT_SECRET'];
  const examples = exampleValues();
  for (const name of names) {
    const value = env[name];
    if (!value) throw new Error(`${name} must be set in production`);
    if (value.trim().length < 32) throw new Error(`${name} must be at least 32 characters in production`);
    if (examples.has(value.trim())) throw new Error(`${name} must not use a value from .env.example`);
  }
  const secrets = names.map((name) => env[name].trim());
  if (new Set(secrets).size !== secrets.length) throw new Error('USER_JWT_SECRET, ADMIN_JWT_SECRET and ENTITLEMENT_SECRET must be different values');
  if (!env.ADMIN_PASSWORD || env.ADMIN_PASSWORD.length < 12) {
    throw new Error('ADMIN_PASSWORD must be set to at least 12 characters in production');
  }
  return true;
}

module.exports = { validateProductionEnv };
