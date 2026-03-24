-- Granular permissions

ALTER TABLE user_projects ADD COLUMN permission TEXT NOT NULL DEFAULT 'admin';
ALTER TABLE user_projects ADD COLUMN env_scope TEXT DEFAULT NULL;
