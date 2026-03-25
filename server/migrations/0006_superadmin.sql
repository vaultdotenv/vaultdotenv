-- Superadmin flag
ALTER TABLE users ADD COLUMN is_superadmin INTEGER NOT NULL DEFAULT 0;

-- Make Matt a superadmin
UPDATE users SET is_superadmin = 1 WHERE email = 'matt@vaultdotenv.io';
