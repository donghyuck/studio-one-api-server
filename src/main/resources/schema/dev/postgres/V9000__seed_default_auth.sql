-- Dev-only seed data (loaded via spring.flyway.locations in application-dev.yml)
-- Creates default roles, group, and an admin user for local development.

-- Roles
INSERT INTO studioapi.tb_application_role (name, description)
VALUES
  ('ROLE_ADMIN', 'Administrator'),
  ('ROLE_MANAGER', 'Manager'),
  ('ROLE_DEVELOPER', 'Developer')
ON CONFLICT (name) DO NOTHING;

-- Default group
INSERT INTO studioapi.tb_application_group (name, description)
VALUES ('default', 'Default group')
ON CONFLICT (name) DO NOTHING;

-- Default admin user
-- Password: studioapi
-- BCrypt (cost 10): $2y$10$99oNsR.m4nrLCcLfBvowqO451JYznC39K0Xj/vjpfitSwLgADujUG
INSERT INTO studioapi.tb_application_user (username, password_hash, email, name)
VALUES ('admin', '$2y$10$99oNsR.m4nrLCcLfBvowqO451JYznC39K0Xj/vjpfitSwLgADujUG', 'admin@studio.local', 'Admin')
ON CONFLICT (username) DO NOTHING;

-- Map admin -> ROLE_ADMIN
INSERT INTO studioapi.tb_application_user_roles (user_id, role_id, assigned_by)
SELECT u.user_id, r.role_id, 'seed'
FROM studioapi.tb_application_user u
JOIN studioapi.tb_application_role r ON r.name = 'ROLE_ADMIN'
WHERE u.username = 'admin'
ON CONFLICT (user_id, role_id) DO NOTHING;

-- Map admin -> ROLE_DEVELOPER
INSERT INTO studioapi.tb_application_user_roles (user_id, role_id, assigned_by)
SELECT u.user_id, r.role_id, 'seed'
FROM studioapi.tb_application_user u
JOIN studioapi.tb_application_role r ON r.name = 'ROLE_DEVELOPER'
WHERE u.username = 'admin'
ON CONFLICT (user_id, role_id) DO NOTHING;

-- Add admin to default group
INSERT INTO studioapi.tb_application_group_members (group_id, user_id, joined_by)
SELECT g.group_id, u.user_id, 'seed'
FROM studioapi.tb_application_group g
JOIN studioapi.tb_application_user u ON u.username = 'admin'
WHERE g.name = 'default'
ON CONFLICT (group_id, user_id) DO NOTHING;

-- Grant default group -> ROLE_MANAGER
INSERT INTO studioapi.tb_application_group_roles (group_id, role_id, assigned_by)
SELECT g.group_id, r.role_id, 'seed'
FROM studioapi.tb_application_group g
JOIN studioapi.tb_application_role r ON r.name = 'ROLE_MANAGER'
WHERE g.name = 'default'
ON CONFLICT (group_id, role_id) DO NOTHING;
