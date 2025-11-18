// backend/config/env.js
const requiredEnvVars = [
  'DATABASE_URL',
  'JWT_SECRET_KEY', 
  'SECRET_KEY',
  'CLOUDINARY_CLOUD_NAME',
  'CLOUDINARY_API_KEY',
  'CLOUDINARY_API_SECRET',
  'GMAIL_USER',
  'GMAIL_PASS'
];

const optionalEnvVars = [
  'GROQ_API_KEY',
  'HF_API_KEY',
  'GROQ_MODEL',
  'HF_MODEL'
];

function validateEnvironment() {
  const missing = [];
  
  requiredEnvVars.forEach(varName => {
    if (!process.env[varName]) {
      missing.push(varName);
    }
  });

  if (missing.length > 0) {
    throw new Error(`❌ Missing required environment variables: ${missing.join(', ')}`);
  }

  // Log optional env vars status
  optionalEnvVars.forEach(varName => {
    if (!process.env[varName]) {
      console.warn(`⚠️ Optional environment variable not set: ${varName}`);
    }
  });

  console.log('✅ Environment validation passed');
}

function getDatabaseUrl() {
  let dbUrl = process.env.DATABASE_URL;
  
  if (dbUrl && dbUrl.startsWith("postgres://")) {
    dbUrl = dbUrl.replace("postgres://", "postgresql+psycopg2://", 1);
  }
  
  return dbUrl || "postgresql+psycopg2://sirverse_user:sirverse123@localhost:5432/sirverse_gpt_db";
}

module.exports = {
  validateEnvironment,
  getDatabaseUrl,
  requiredEnvVars,
  optionalEnvVars
};
