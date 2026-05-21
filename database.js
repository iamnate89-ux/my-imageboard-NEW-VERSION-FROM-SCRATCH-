const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./imageboard.db');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS boards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS threads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    board_slug TEXT NOT NULL,
    subject TEXT,
    pinned INTEGER DEFAULT 0,
    locked INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    bumped_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    thread_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    image_path TEXT,
    ip_address TEXT,
    country TEXT,
    staff_role TEXT,
    staff_name TEXT,
    image_mature INTEGER DEFAULT 0,
    deleted INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (thread_id) REFERENCES threads(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS staff (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin', 'janitor')),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS bans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    reason TEXT,
    banned_by TEXT,
    expires_at DATETIME,
    post_id INTEGER,
    post_content TEXT,
    post_image TEXT,
    ban_scope TEXT NOT NULL DEFAULT 'all',
    ban_board TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    thread_id INTEGER NOT NULL,
    board_slug TEXT NOT NULL,
    reason TEXT NOT NULL,
    reporter_ip TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    resolved_by TEXT,
    resolved_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS mod_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    staff_username TEXT NOT NULL,
    action TEXT NOT NULL,
    target_id INTEGER,
    note TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS appeals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ban_id INTEGER NOT NULL,
    ip_address TEXT NOT NULL,
    message TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    reviewed_by TEXT,
    reviewed_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (ban_id) REFERENCES bans(id)
  )`);

  // Safely add new columns to existing databases
  db.run(`ALTER TABLE posts ADD COLUMN country TEXT`, () => {});
  db.run(`ALTER TABLE posts ADD COLUMN staff_role TEXT`, () => {});
  db.run(`ALTER TABLE posts ADD COLUMN staff_name TEXT`, () => {});
  db.run(`ALTER TABLE posts ADD COLUMN image_mature INTEGER DEFAULT 0`, () => {});
  db.run(`ALTER TABLE threads ADD COLUMN pinned INTEGER DEFAULT 0`, () => {});
  db.run(`ALTER TABLE threads ADD COLUMN locked INTEGER DEFAULT 0`, () => {});

  db.run(`INSERT OR IGNORE INTO boards (slug, name, description) VALUES ('b', 'Random', 'Anything goes')`);
  db.run(`INSERT OR IGNORE INTO boards (slug, name, description) VALUES ('pol', 'Politically Incorrect', 'Political discussion')`);
  db.run(`ALTER TABLE posts ADD COLUMN delete_password TEXT`, () => {});
});

module.exports = db;