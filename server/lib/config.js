/**
 * Shared configuration constants.
 */

export const DASHBOARD_URL = 'https://app.vaultdotenv.io';
export const HMAC_MAX_AGE_MS = 300_000; // 5 minutes
export const SESSION_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
export const CLI_AUTH_EXPIRY_MS = 10 * 60 * 1000; // 10 minutes
export const INVITE_EXPIRY_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
export const REVEAL_TOKEN_TTL_MS = 60_000; // 60 seconds
export const PBKDF2_ITERATIONS = 100_000;

export const PLAN_LIMITS = {
  free:  { secrets: 10, environments: 2, projects: 1, devices: 2 },
  pro:   { secrets: 30, environments: 3, projects: 3, devices: 5 },
  team:  { secrets: 100, environments: -1, projects: 10, devices: -1 }, // -1 = unlimited
};

export const EMAIL_FROM = 'vaultdotenv <noreply@vaultdotenv.io>';
