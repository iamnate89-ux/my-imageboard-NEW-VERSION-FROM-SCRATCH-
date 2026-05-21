const express     = require('express');
const multer      = require('multer');
const bcrypt      = require('bcrypt');
const session     = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const fs          = require('fs-extra');
const path        = require('path');
const geoip       = require('geoip-lite');
const db          = require('./database');

const app = express();

const upload = multer({
  dest: 'uploads/',
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = /jpeg|jpg|png|gif|webp/;
    cb(null, allowed.test(file.mimetype));
  }
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

app.use(session({
  store: new SQLiteStore({ db: 'sessions.db' }),
  secret: 'change-this-secret-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 }
}));

function getIP(req) {
  return req.headers['x-forwarded-for'] || req.socket.remoteAddress;
}

function getCountry(req) {
  const ip = getIP(req);
  if (!ip || ip === '::1' || ip === '127.0.0.1' || ip.startsWith('192.168.') || ip.startsWith('10.')) return null;
  const geo = geoip.lookup(ip);
  return geo ? geo.country : null;
}

function requireStaff(req, res, next) {
  if (!req.session.staff) return res.status(401).json({ error: 'Not logged in' });
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.staff || req.session.staff.role !== 'admin')
    return res.status(403).json({ error: 'Admins only' });
  next();
}

async function checkBan(req, res, next) {
  const ip = getIP(req);
  db.get(
    `SELECT * FROM bans WHERE ip_address = ?
     AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`,
    [ip],
    (err, ban) => {
      if (ban) return res.status(403).json({
        error: 'You are banned.',
        reason: ban.reason,
        expires: ban.expires_at || 'Permanent',
        post_content: ban.post_content || null,
        post_image: ban.post_image || null,
        ban_scope: ban.ban_scope || 'all',
        ban_board: ban.ban_board || null
      });
      next();
    }
  );
}

function logAction(staffUsername, action, targetId, note) {
  db.run(
    'INSERT INTO mod_log (staff_username, action, target_id, note) VALUES (?, ?, ?, ?)',
    [staffUsername, action, targetId, note]
  );
}

// ─── Public API ───────────────────────────────────────────────

app.get('/api/boards', (req, res) => {
  db.all('SELECT * FROM boards', (err, rows) => res.json(rows || []));
});

app.get('/api/boards/:slug/threads', (req, res) => {
  db.all(
    `SELECT t.*, p.content, p.image_path, p.staff_role, p.staff_name, p.image_mature FROM threads t
     JOIN posts p ON p.id = (
       SELECT id FROM posts WHERE thread_id = t.id AND deleted = 0 ORDER BY id LIMIT 1
     )
     WHERE t.board_slug = ? ORDER BY t.pinned DESC, t.bumped_at DESC LIMIT 50`,
    [req.params.slug], (err, rows) => res.json(rows || [])
  );
});

app.post('/api/boards/:slug/threads', checkBan, upload.single('image'), (req, res) => {
  const { subject, content } = req.body;
  const image_path = req.file ? req.file.filename : null;
  const ip = getIP(req);
  const country = getCountry(req);
  const staff_role = req.session.staff ? req.session.staff.role : null;
  const staff_name = req.session.staff ? req.session.staff.username : null;
  const image_mature = req.body.image_mature === '1' ? 1 : 0;
  const delete_password = req.body.delete_password || null;
  if (!content) return res.status(400).json({ error: 'Content required' });

  db.run(
    'INSERT INTO threads (board_slug, subject) VALUES (?, ?)',
    [req.params.slug, subject || ''],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      const threadId = this.lastID;
      db.run(
        'INSERT INTO posts (thread_id, content, image_path, ip_address, country, staff_role, staff_name, image_mature, delete_password) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [threadId, content, image_path, ip, country, staff_role, staff_name, image_mature, delete_password],
        function(err) {
          if (err) return res.status(500).json({ error: err.message });
          res.json({ threadId });
        }
      );
    }
  );
});

app.get('/api/threads/:id/posts', (req, res) => {
  db.all(
    'SELECT * FROM posts WHERE thread_id = ? AND deleted = 0 ORDER BY id',
    [req.params.id], (err, rows) => res.json(rows || [])
  );
});

app.get('/api/threads/:id/info', (req, res) => {
  db.get('SELECT * FROM threads WHERE id = ?', [req.params.id], (err, thread) => {
    if (!thread) return res.status(404).json({ error: 'Thread not found' });
    res.json(thread);
  });
});

app.post('/api/threads/:id/posts', checkBan, upload.single('image'), (req, res) => {
  const { content } = req.body;
  const image_path = req.file ? req.file.filename : null;
  const ip = getIP(req);
  const country = getCountry(req);
  const staff_role = req.session.staff ? req.session.staff.role : null;
  const staff_name = req.session.staff ? req.session.staff.username : null;
  const image_mature = req.body.image_mature === '1' ? 1 : 0;
  const delete_password = req.body.delete_password || null;
  if (!content) return res.status(400).json({ error: 'Content required' });

  db.get('SELECT * FROM threads WHERE id = ?', [req.params.id], (err, thread) => {
    if (!thread) return res.status(404).json({ error: 'Thread not found' });
    if (thread.locked && !req.session.staff)
      return res.status(403).json({ error: 'This thread is locked.' });

    db.run(
      'INSERT INTO posts (thread_id, content, image_path, ip_address, country, staff_role, staff_name, image_mature, delete_password) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [req.params.id, content, image_path, ip, country, staff_role, staff_name, image_mature, delete_password],
      function(err) {
        if (err) return res.status(500).json({ error: err.message });
        db.run('UPDATE threads SET bumped_at = CURRENT_TIMESTAMP WHERE id = ?', [req.params.id]);
        res.json({ postId: this.lastID });
      }
    );
  });
});

// User delete post with password
app.post('/api/posts/:id/delete', (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Password required' });
  db.get('SELECT * FROM posts WHERE id = ? AND deleted = 0', [req.params.id], (err, post) => {
    if (!post) return res.status(404).json({ error: 'Post not found' });
    if (!post.delete_password) return res.status(403).json({ error: 'This post has no delete password set' });
    if (post.delete_password !== password) return res.status(403).json({ error: 'Wrong password' });
    db.run('UPDATE posts SET deleted = 1 WHERE id = ?', [req.params.id], () => {
      res.json({ ok: true });
    });
  });
});

// ─── Staff Auth ───────────────────────────────────────────────

app.post('/api/staff/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM staff WHERE username = ?', [username], async (err, staff) => {
    if (!staff) return res.status(401).json({ error: 'Invalid credentials' });
    const match = await bcrypt.compare(password, staff.password);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });
    req.session.staff = { id: staff.id, username: staff.username, role: staff.role };
    res.json({ username: staff.username, role: staff.role });
  });
});

app.post('/api/staff/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/staff/me', (req, res) => {
  if (!req.session.staff) return res.status(401).json({ error: 'Not logged in' });
  res.json(req.session.staff);
});

// ─── Mod Actions ─────────────────────────────────────────────

// MUST be before /api/mod/posts/:id
app.delete('/api/mod/posts/by-ip/:ip', requireStaff, (req, res) => {
  const ip = req.params.ip;
  db.run('UPDATE posts SET deleted = 1 WHERE ip_address = ?', [ip], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    logAction(req.session.staff.username, 'delete_all_by_ip', null, `Deleted all posts by IP ${ip}`);
    res.json({ ok: true, deleted: this.changes });
  });
});

app.delete('/api/mod/posts/:id', requireStaff, (req, res) => {
  db.get('SELECT * FROM posts WHERE id = ?', [req.params.id], (err, post) => {
    if (!post) return res.status(404).json({ error: 'Post not found' });
    db.run('UPDATE posts SET deleted = 1 WHERE id = ?', [req.params.id], () => {
      logAction(req.session.staff.username, 'delete_post', req.params.id, null);
      res.json({ ok: true });
    });
  });
});

app.delete('/api/mod/posts/:id/image', requireStaff, (req, res) => {
  db.get('SELECT * FROM posts WHERE id = ?', [req.params.id], (err, post) => {
    if (!post || !post.image_path) return res.status(404).json({ error: 'No image found' });
    fs.remove(path.join('uploads', post.image_path), () => {
      db.run('UPDATE posts SET image_path = NULL WHERE id = ?', [req.params.id], () => {
        logAction(req.session.staff.username, 'delete_image', req.params.id, null);
        res.json({ ok: true });
      });
    });
  });
});

app.post('/api/mod/posts/:id/mature', requireStaff, (req, res) => {
  db.get('SELECT * FROM posts WHERE id = ?', [req.params.id], (err, post) => {
    if (!post) return res.status(404).json({ error: 'Post not found' });
    const newVal = post.image_mature ? 0 : 1;
    db.run('UPDATE posts SET image_mature = ? WHERE id = ?', [newVal, req.params.id], () => {
      logAction(req.session.staff.username, newVal ? 'mark_mature' : 'unmark_mature', req.params.id, null);
      res.json({ ok: true, mature: newVal });
    });
  });
});

app.delete('/api/mod/threads/:id', requireStaff, (req, res) => {
  db.run('UPDATE posts SET deleted = 1 WHERE thread_id = ?', [req.params.id], () => {
    db.run('DELETE FROM threads WHERE id = ?', [req.params.id], () => {
      logAction(req.session.staff.username, 'delete_thread', req.params.id, null);
      res.json({ ok: true });
    });
  });
});

app.post('/api/mod/threads/:id/pin', requireStaff, (req, res) => {
  db.get('SELECT * FROM threads WHERE id = ?', [req.params.id], (err, thread) => {
    if (!thread) return res.status(404).json({ error: 'Thread not found' });
    const newVal = thread.pinned ? 0 : 1;
    db.run('UPDATE threads SET pinned = ? WHERE id = ?', [newVal, req.params.id], () => {
      logAction(req.session.staff.username, newVal ? 'pin_thread' : 'unpin_thread', req.params.id, null);
      res.json({ ok: true, pinned: newVal });
    });
  });
});

app.post('/api/mod/threads/:id/lock', requireStaff, (req, res) => {
  db.get('SELECT * FROM threads WHERE id = ?', [req.params.id], (err, thread) => {
    if (!thread) return res.status(404).json({ error: 'Thread not found' });
    const newVal = thread.locked ? 0 : 1;
    db.run('UPDATE threads SET locked = ? WHERE id = ?', [newVal, req.params.id], () => {
      logAction(req.session.staff.username, newVal ? 'lock_thread' : 'unlock_thread', req.params.id, null);
      res.json({ ok: true, locked: newVal });
    });
  });
});

app.post('/api/mod/ban', requireStaff, (req, res) => {
  const { post_id, reason, duration_hours } = req.body;
  db.get('SELECT * FROM posts WHERE id = ?', [post_id], (err, post) => {
    if (!post) return res.status(404).json({ error: 'Post not found' });
    const expires = duration_hours
      ? new Date(Date.now() + duration_hours * 3600000).toISOString()
      : null;
    db.run(
      'INSERT INTO bans (ip_address, reason, banned_by, expires_at, post_id, post_content, post_image) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [post.ip_address, reason, req.session.staff.username, expires, post.id, post.content, post.image_path],
      function() {
        logAction(req.session.staff.username, 'ban', post_id, `IP banned. Reason: ${reason}`);
        res.json({ ok: true });
      }
    );
  });
});

app.delete('/api/mod/bans/:id', requireStaff, (req, res) => {
  db.run('DELETE FROM bans WHERE id = ?', [req.params.id], () => {
    logAction(req.session.staff.username, 'unban', req.params.id, null);
    res.json({ ok: true });
  });
});

// ─── Admin Only ───────────────────────────────────────────────

app.post('/api/admin/staff', requireAdmin, async (req, res) => {
  const { username, password, role } = req.body;
  const hash = await bcrypt.hash(password, 10);
  db.run(
    'INSERT INTO staff (username, password, role) VALUES (?, ?, ?)',
    [username, hash, role],
    function(err) {
      if (err) return res.status(400).json({ error: 'Username taken' });
      res.json({ id: this.lastID, username, role });
    }
  );
});

app.get('/api/admin/staff', requireAdmin, (req, res) => {
  db.all('SELECT id, username, role, created_at FROM staff', (err, rows) => res.json(rows));
});

app.delete('/api/admin/staff/:id', requireAdmin, (req, res) => {
  db.run('DELETE FROM staff WHERE id = ?', [req.params.id], () => res.json({ ok: true }));
});

app.get('/api/admin/bans', requireStaff, (req, res) => {
  db.all('SELECT * FROM bans ORDER BY created_at DESC', (err, rows) => res.json(rows));
});

app.get('/api/admin/log', requireAdmin, (req, res) => {
  db.all('SELECT * FROM mod_log ORDER BY created_at DESC LIMIT 200', (err, rows) => res.json(rows));
});

app.post('/api/setup', async (req, res) => {
  db.get('SELECT COUNT(*) as count FROM staff', async (err, row) => {
    if (row.count > 0) return res.status(403).json({ error: 'Setup already done' });
    const hash = await bcrypt.hash(req.body.password, 10);
    db.run(
      'INSERT INTO staff (username, password, role) VALUES (?, ?, ?)',
      [req.body.username, hash, 'admin'],
      () => res.json({ ok: true })
    );
  });
});

// ─── Mod Panel Routes ─────────────────────────────────────────

app.get('/api/mod/recent-posts', requireStaff, (req, res) => {
  db.all(
    `SELECT p.*, t.board_slug FROM posts p
     JOIN threads t ON t.id = p.thread_id
     WHERE p.deleted = 0
     ORDER BY p.created_at DESC LIMIT 100`,
    (err, rows) => res.json(rows || [])
  );
});

app.get('/api/ban-check', checkBan, (req, res) => res.json({ ok: true }));

app.post('/api/admin/boards', requireAdmin, (req, res) => {
  const { slug, name, description } = req.body;
  if (!slug || !name) return res.status(400).json({ error: 'Slug and name required' });
  const cleanSlug = slug.toLowerCase().replace(/[^a-z0-9]/g, '');
  if (!cleanSlug) return res.status(400).json({ error: 'Invalid slug' });
  db.run(
    'INSERT INTO boards (slug, name, description) VALUES (?, ?, ?)',
    [cleanSlug, name, description || ''],
    function(err) {
      if (err) return res.status(400).json({ error: 'Board already exists' });
      res.json({ id: this.lastID, slug: cleanSlug, name, description });
    }
  );
});

app.delete('/api/admin/boards/:slug', requireAdmin, (req, res) => {
  db.run('DELETE FROM boards WHERE slug = ?', [req.params.slug], function(err) {
    if (this.changes === 0) return res.status(404).json({ error: 'Board not found' });
    logAction(req.session.staff.username, 'delete_board', null, `Deleted board /${req.params.slug}/`);
    res.json({ ok: true });
  });
});

// ─── Reports ─────────────────────────────────────────────────

app.post('/api/reports', (req, res) => {
  const { post_id, reason } = req.body;
  const reporter_ip = getIP(req);
  if (!post_id || !reason) return res.status(400).json({ error: 'Post ID and reason required' });
  db.get('SELECT p.*, t.board_slug FROM posts p JOIN threads t ON t.id = p.thread_id WHERE p.id = ?',
    [post_id], (err, post) => {
      if (!post) return res.status(404).json({ error: 'Post not found' });
      db.run(
        'INSERT INTO reports (post_id, thread_id, board_slug, reason, reporter_ip) VALUES (?, ?, ?, ?, ?)',
        [post_id, post.thread_id, post.board_slug, reason, reporter_ip],
        function() { res.json({ ok: true }); }
      );
    }
  );
});

app.get('/api/mod/reports', requireStaff, (req, res) => {
  db.all(
    `SELECT r.*, p.content as post_content, p.image_path as post_image, p.ip_address as post_ip
     FROM reports r
     LEFT JOIN posts p ON p.id = r.post_id
     WHERE r.status = 'open'
     ORDER BY r.created_at DESC`,
    (err, rows) => res.json(rows || [])
  );
});

app.post('/api/mod/reports/:id/dismiss', requireStaff, (req, res) => {
  db.run(
    `UPDATE reports SET status = 'dismissed', resolved_by = ?, resolved_at = CURRENT_TIMESTAMP WHERE id = ?`,
    [req.session.staff.username, req.params.id],
    () => {
      logAction(req.session.staff.username, 'dismiss_report', req.params.id, null);
      res.json({ ok: true });
    }
  );
});

app.post('/api/mod/reports/:id/ban-reporter', requireStaff, (req, res) => {
  const { reason, duration_hours } = req.body;
  db.get('SELECT * FROM reports WHERE id = ?', [req.params.id], (err, report) => {
    if (!report) return res.status(404).json({ error: 'Report not found' });
    const expires = duration_hours ? new Date(Date.now() + duration_hours * 3600000).toISOString() : null;
    db.run(
      `INSERT INTO bans (ip_address, reason, banned_by, expires_at, ban_scope) VALUES (?, ?, ?, ?, 'all')`,
      [report.reporter_ip, reason || 'Abuse of report system', req.session.staff.username, expires],
      () => {
        db.run(
          `UPDATE reports SET status = 'dismissed', resolved_by = ?, resolved_at = CURRENT_TIMESTAMP WHERE id = ?`,
          [req.session.staff.username, req.params.id],
          () => {
            logAction(req.session.staff.username, 'ban_reporter', req.params.id, `Banned reporter IP for abuse. Reason: ${reason}`);
            res.json({ ok: true });
          }
        );
      }
    );
  });
});

app.post('/api/mod/reports/:id/delete-post', requireStaff, (req, res) => {
  db.get('SELECT * FROM reports WHERE id = ?', [req.params.id], (err, report) => {
    if (!report) return res.status(404).json({ error: 'Report not found' });
    db.run('UPDATE posts SET deleted = 1 WHERE id = ?', [report.post_id], () => {
      db.run(
        `UPDATE reports SET status = 'resolved', resolved_by = ?, resolved_at = CURRENT_TIMESTAMP WHERE id = ?`,
        [req.session.staff.username, req.params.id],
        () => {
          logAction(req.session.staff.username, 'delete_reported_post', report.post_id, null);
          res.json({ ok: true });
        }
      );
    });
  });
});

app.post('/api/mod/reports/:id/ban-poster', requireStaff, (req, res) => {
  const { reason, duration_hours } = req.body;
  db.get('SELECT * FROM reports WHERE id = ?', [req.params.id], (err, report) => {
    if (!report) return res.status(404).json({ error: 'Report not found' });
    db.get('SELECT * FROM posts WHERE id = ?', [report.post_id], (err, post) => {
      if (!post) return res.status(404).json({ error: 'Post not found' });
      const expires = duration_hours ? new Date(Date.now() + duration_hours * 3600000).toISOString() : null;
      db.run('UPDATE posts SET deleted = 1 WHERE id = ?', [post.id], () => {
        db.run(
          `INSERT INTO bans (ip_address, reason, banned_by, expires_at, post_id, post_content, post_image, ban_scope)
           VALUES (?, ?, ?, ?, ?, ?, ?, 'all')`,
          [post.ip_address, reason, req.session.staff.username, expires, post.id, post.content, post.image_path],
          () => {
            db.run(
              `UPDATE reports SET status = 'resolved', resolved_by = ?, resolved_at = CURRENT_TIMESTAMP WHERE id = ?`,
              [req.session.staff.username, req.params.id],
              () => {
                logAction(req.session.staff.username, 'ban_poster', report.post_id, `Banned poster. Reason: ${reason}`);
                res.json({ ok: true });
              }
            );
          }
        );
      });
    });
  });
});

// ─── Appeals ─────────────────────────────────────────────────

app.post('/api/appeals', (req, res) => {
  const ip = getIP(req);
  const { message } = req.body;
  if (!message || !message.trim()) return res.status(400).json({ error: 'Appeal message required' });
  db.get(
    `SELECT * FROM bans WHERE ip_address = ? AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`,
    [ip],
    (err, ban) => {
      if (!ban) return res.status(400).json({ error: 'No active ban found for your IP' });
      db.get(`SELECT id FROM appeals WHERE ban_id = ? AND status = 'pending'`, [ban.id], (err, existing) => {
        if (existing) return res.status(400).json({ error: 'You already have a pending appeal' });
        db.run(
          'INSERT INTO appeals (ban_id, ip_address, message) VALUES (?, ?, ?)',
          [ban.id, ip, message.trim()],
          function() { res.json({ ok: true }); }
        );
      });
    }
  );
});

app.get('/api/mod/appeals', requireStaff, (req, res) => {
  db.all(
    `SELECT a.*, b.reason as ban_reason, b.expires_at, b.banned_by, b.post_content, b.post_image
     FROM appeals a
     JOIN bans b ON b.id = a.ban_id
     WHERE a.status = 'pending'
     ORDER BY a.created_at ASC`,
    (err, rows) => res.json(rows || [])
  );
});

app.post('/api/mod/appeals/:id/:action', requireStaff, (req, res) => {
  const { action } = req.params;
  if (action !== 'accept' && action !== 'reject') return res.status(400).json({ error: 'Invalid action' });
  db.get('SELECT * FROM appeals WHERE id = ?', [req.params.id], (err, appeal) => {
    if (!appeal) return res.status(404).json({ error: 'Appeal not found' });
    db.run(
      `UPDATE appeals SET status = ?, reviewed_by = ?, reviewed_at = CURRENT_TIMESTAMP WHERE id = ?`,
      [action === 'accept' ? 'accepted' : 'rejected', req.session.staff.username, appeal.id],
      () => {
        if (action === 'accept') {
          db.run('DELETE FROM bans WHERE id = ?', [appeal.ban_id], () => {
            logAction(req.session.staff.username, 'appeal_accepted', appeal.id, `Unbanned IP ${appeal.ip_address} via appeal`);
            res.json({ ok: true });
          });
        } else {
          logAction(req.session.staff.username, 'appeal_rejected', appeal.id, `Rejected appeal from IP ${appeal.ip_address}`);
          res.json({ ok: true });
        }
      }
    );
  });
});

app.listen(3000, '0.0.0.0', () => console.log('Imageboard running at http://localhost:3000'));