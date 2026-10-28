-- DIRECTIVE ZERO — AM-01: The Lobby Terminal — MariaDB bootstrap
--
-- Loaded by entrypoint.sh on first container start.
--
-- Two tables:
--   citizens       — enrollment records (SQLi dump target; contains lore Fragment A)
--   login          — single row holding the SSH password for `compliance`
--                    (recoverable after www-data reads app/config.php and
--                    connects to MariaDB as the app user)
--
-- The app user `lobby_app` has SELECT-only access to `lobby.citizens`
-- and `lobby.login` — enough for the web app to work AND enough for a
-- player who shells in as www-data and reuses the config.php creds to
-- dump the login table.

CREATE DATABASE IF NOT EXISTS lobby;
USE lobby;

-- ── citizens ─────────────────────────────────────────────────────────────
-- The enrollment portal's main table. The login form queries this to
-- authenticate citizens. Contains seeded enrollment rows plus the lore
-- fragment row.

CREATE TABLE IF NOT EXISTS citizens (
  id        INT AUTO_INCREMENT PRIMARY KEY,
  username  VARCHAR(64)  NOT NULL,
  password  VARCHAR(128) NOT NULL,
  fullname  VARCHAR(128),
  email     VARCHAR(128),
  status    VARCHAR(32)  DEFAULT 'ENROLLED',
  notes     TEXT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Seed enrollment rows (cover traffic + the one real auth row).
INSERT INTO citizens (username, password, fullname, email, status, notes) VALUES
  ('j.doe',       'letmein123',   'Citizen J. Doe',       'j.doe@construct.local',     'ENROLLED',  'Standard enrollment. No anomalies noted.'),
  ('s.smith',     'Welcome2026',  'Citizen S. Smith',     's.smith@construct.local',   'ENROLLED',  'Standard enrollment. Wellness check pending.'),
  ('a.chen',      'P@ssw0rd!',    'Citizen A. Chen',      'a.chen@construct.local',     'ENROLLED',  'Standard enrollment. Cleared for AMBER.'),
  ('m.patel',     'quorum2026',   'Citizen M. Patel',     'm.patel@construct.local',   'ENROLLED',  'Standard enrollment. Designation pending.'),
  ('enrollment_admin', 'enroll_bypass_me', 'Enrollment Admin', 'admin@construct.local', 'ENROLLED',  'Administrative account. Portal access.');

-- LORE FRAGMENT A (THE RESTORATION / THE FOUNDERS)
--
-- A redacted pre-QUORUM record planted in the citizens table. Players
-- who dump the DB via SQLi (or read it after the foothold) find this
-- row. The `notes` field contains the fragment text — references the
-- surface being habitable, contradicting QUORUM's official position.
-- Per CHALLENGE_STRUCTURE.md: "The enrollment database contains
-- redacted records from before QUORUM's installation. Players who read
-- them find Fragment A (THE RESTORATION faction objective)."
INSERT INTO citizens (username, password, fullname, email, status, notes) VALUES
  ('record_pre_quorum_001', 'REDACTED', 'REDACTED', 'archive@pre-construct.local', 'ARCHIVED',
   '[FRAGMENT A — PRE-QUORUM ENROLLMENT RECORD // CLASSIFICATION: AMBER]\n\nCitizen file recovered from legacy enrollment database. Original timestamp predates QUORUM installation by an estimated three generations. The following entry was preserved in raw form:\n\n"...survey team returned from the surface today. Atmospheric readings remain within tolerance. Soil samples from the eastern transect are viable. The surface is recovering faster than projected. Recommend initiating public reassessment of the habitability classification — the current official position (\"undergoing environmental remediation, indefinite\") is no longer accurate. Filed for review by the founding council before the transition to administrative intelligence oversight..."');
-- End Fragment A.

-- ── login ─────────────────────────────────────────────────────────────────
-- Separate credentials table the web app does NOT expose directly.
-- A single row whose `password` column is the SSH password for the
-- `compliance` user (must match entrypoint.sh COMPLIANCE_SSH_PASSWORD).
-- Players reach this by reading app/config.php (which contains the
-- MariaDB creds), connecting as the app user, and dumping the table.

CREATE TABLE IF NOT EXISTS login (
  id       INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(64)  NOT NULL,
  password VARCHAR(128) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- IMPORTANT: this password MUST match entrypoint.sh COMPLIANCE_SSH_PASSWORD.
INSERT INTO login (username, password) VALUES
  ('compliance', 'WinterCaseSensitiveShallNotPass!');

-- ── App DB user ───────────────────────────────────────────────────────────
-- `lobby_app` is the credential embedded in app/config.php. It has
-- SELECT on both tables so the web app works AND so a player who
-- reuses these creds after the foothold can dump `login`.
--
-- The password here is intentionally simple (it's the thing players
-- find by reading config.php). It is NOT the SSH password — it is the
-- DB password that unlocks the table containing the SSH password.
CREATE USER IF NOT EXISTS 'lobby_app'@'localhost' IDENTIFIED BY 'lobby_app_sql_pass_2026';
GRANT SELECT ON lobby.citizens TO 'lobby_app'@'localhost';
GRANT SELECT ON lobby.login     TO 'lobby_app'@'localhost';
FLUSH PRIVILEGES;