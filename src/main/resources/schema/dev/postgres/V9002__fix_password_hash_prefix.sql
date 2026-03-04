-- Dev-only fix:
-- Spring Security DelegatingPasswordEncoder requires "{id}" prefix (e.g. "{bcrypt}...").
-- If legacy rows were seeded without a prefix, login fails with:
--   "There is no PasswordEncoder mapped for the id \"null\""

UPDATE studioapi.tb_application_user
SET password_hash = '{bcrypt}' || password_hash
WHERE password_hash IS NOT NULL
  AND password_hash NOT LIKE '{%}%'
  AND password_hash LIKE '$2%$%';
