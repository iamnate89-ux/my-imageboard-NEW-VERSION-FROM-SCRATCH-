const express     = require('express');
const multer      = require('multer');
const bcrypt      = require('bcrypt');
const session     = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const fs          = require('fs-extra');
const path        = require('path');
const crypto      = require('crypto');
const geoip       = require('geoip-lite');
const db          = require('./database');

const app = express();
const LEGAL_INCIDENTS_CLEAN_SLATE_AT = '2026-06-06 19:05:00';
const geoOverridesPath = path.join(__dirname, 'geo-overrides.json');

function loadGeoOverrides() {
  try {
    return JSON.parse(fs.readFileSync(geoOverridesPath, 'utf8'))
      .filter(entry => entry && entry.match && /^[A-Z]{2}$/.test(String(entry.country || '').toUpperCase()))
      .map(entry => ({
        match: String(entry.match).trim(),
        country: String(entry.country).trim().toUpperCase(),
        note: entry.note || ''
      }));
  } catch {
    return [];
  }
}

const geoOverrides = loadGeoOverrides();

const uploadStorage = multer.diskStorage({
  destination: 'uploads/',
  filename: (req, file, cb) => {
    const extByMime = {
      'image/jpeg': '.jpg',
      'image/png': '.png',
      'image/gif': '.gif',
      'image/webp': '.webp'
    };
    cb(null, `${crypto.randomBytes(16).toString('hex')}${extByMime[file.mimetype] || ''}`);
  }
});

const upload = multer({
  storage: uploadStorage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    cb(null, allowed.includes(file.mimetype));
  }
});

geoOverrides
  .filter(entry => !entry.match.includes('/'))
  .forEach(entry => {
    db.run(
      'UPDATE posts SET country = ? WHERE ip_address = ? AND (country IS NULL OR country != ?)',
      [entry.country, normalizeIP(entry.match), entry.country],
      () => {}
    );
  });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

function imageContentType(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  if (ext === '.jpg' || ext === '.jpeg') return 'image/jpeg';
  if (ext === '.png') return 'image/png';
  if (ext === '.gif') return 'image/gif';
  if (ext === '.webp') return 'image/webp';

  const header = fs.readFileSync(filePath, { encoding: null, flag: 'r' }).subarray(0, 12);
  if (header[0] === 0xff && header[1] === 0xd8 && header[2] === 0xff) return 'image/jpeg';
  if (header.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return 'image/png';
  if (header.subarray(0, 3).toString() === 'GIF') return 'image/gif';
  if (header.subarray(0, 4).toString() === 'RIFF' && header.subarray(8, 12).toString() === 'WEBP') return 'image/webp';
  return null;
}

function escapeLike(value) {
  return String(value || '').replace(/[\\%_]/g, match => `\\${match}`);
}

function parsePosterIdentity(rawName) {
  const raw = String(rawName || '').trim().slice(0, 80);
  const hashIndex = raw.indexOf('#');
  const visibleName = hashIndex === -1 ? raw : raw.slice(0, hashIndex).trim();
  const secret = hashIndex === -1 ? '' : raw.slice(hashIndex + 1).trim();
  const posterName = visibleName.slice(0, 40) || 'Anonymous';
  const tripcode = secret
    ? crypto.createHash('sha256').update(secret).digest('base64url').slice(0, 10)
    : null;

  return { posterName, tripcode };
}

function parseIdList(value, limit = 80) {
  return String(value || '')
    .split(',')
    .map(id => Number.parseInt(id, 10))
    .filter(id => Number.isInteger(id) && id > 0)
    .slice(0, limit);
}

app.get('/uploads/:filename', (req, res) => {
  const filename = path.basename(req.params.filename);
  const filePath = path.join(__dirname, 'uploads', filename);
  if (!fs.existsSync(filePath)) return res.status(404).send('Not found');

  const contentType = imageContentType(filePath);
  if (!contentType) return res.status(415).send('Unsupported file');

  const displayName = `${filename}${path.extname(filename) ? '' : contentType.replace('image/', '.')}`;
  res.type(contentType);
  res.setHeader('Content-Disposition', `inline; filename="${displayName}"`);
  res.setHeader('Cache-Control', 'no-store');
  fs.createReadStream(filePath).pipe(res);
});

app.use(session({
  store: new SQLiteStore({ db: 'sessions.db' }),
  secret: process.env.SESSION_SECRET || 'dev-only-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24,
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production'
  }
}));

function getIP(req) {
  const forwarded = req.headers['x-forwarded-for'];
  const raw = Array.isArray(forwarded)
    ? forwarded[0]
    : forwarded || req.socket.remoteAddress;
  return normalizeIP(String(raw).split(',')[0].trim());
}

function normalizeIP(ip) {
  if (!ip) return '';
  let clean = ip.trim().toLowerCase();
  if (clean.startsWith('::ffff:')) clean = clean.slice(7);
  if (clean.startsWith('[')) clean = clean.slice(1, clean.indexOf(']'));
  if (/^\d+\.\d+\.\d+\.\d+:\d+$/.test(clean)) clean = clean.slice(0, clean.lastIndexOf(':'));
  return clean;
}

function expandIPv6(ip) {
  if (!ip || !ip.includes(':')) return null;
  const clean = normalizeIP(ip).split('%')[0];
  const parts = clean.split('::');
  if (parts.length > 2) return null;

  const left = parts[0] ? parts[0].split(':') : [];
  const right = parts[1] ? parts[1].split(':') : [];
  const convertIpv4Tail = segments => {
    const last = segments[segments.length - 1];
    if (!last || !last.includes('.')) return segments;
    const octets = last.split('.').map(Number);
    if (octets.length !== 4 || octets.some(n => Number.isNaN(n) || n < 0 || n > 255)) return segments;
    return [
      ...segments.slice(0, -1),
      ((octets[0] << 8) + octets[1]).toString(16),
      ((octets[2] << 8) + octets[3]).toString(16)
    ];
  };

  const normalizedLeft = convertIpv4Tail(left);
  const normalizedRight = convertIpv4Tail(right);
  const missing = 8 - normalizedLeft.length - normalizedRight.length;
  if (missing < 0 || (parts.length === 1 && missing !== 0)) return null;

  return [
    ...normalizedLeft,
    ...Array(missing).fill('0'),
    ...normalizedRight
  ].map(part => part.padStart(4, '0'));
}

function ipv6Network64(ip) {
  const expanded = expandIPv6(ip);
  return expanded ? expanded.slice(0, 4).join(':') : null;
}

function banAppliesToIP(banIp, requestIp) {
  const normalizedBanIp = normalizeIP(banIp);
  const normalizedRequestIp = normalizeIP(requestIp);
  if (normalizedBanIp === normalizedRequestIp) return true;

  const banNetwork = ipv6Network64(normalizedBanIp);
  const requestNetwork = ipv6Network64(normalizedRequestIp);
  return Boolean(banNetwork && requestNetwork && banNetwork === requestNetwork);
}

function ipv4ToInt(ip) {
  const parts = normalizeIP(ip).split('.');
  if (parts.length !== 4) return null;
  const nums = parts.map(part => Number.parseInt(part, 10));
  if (nums.some(num => !Number.isInteger(num) || num < 0 || num > 255)) return null;
  return nums.reduce((acc, num) => ((acc << 8) + num) >>> 0, 0);
}

function ipv4CidrMatches(ip, cidr) {
  const [base, prefixText] = String(cidr).split('/');
  const prefix = Number.parseInt(prefixText, 10);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return false;
  const ipInt = ipv4ToInt(ip);
  const baseInt = ipv4ToInt(base);
  if (ipInt === null || baseInt === null) return false;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (ipInt & mask) === (baseInt & mask);
}

function countryOverrideForIP(ip) {
  const normalizedIp = normalizeIP(ip);
  const override = geoOverrides.find(entry => {
    if (entry.match.includes('/')) return ipv4CidrMatches(normalizedIp, entry.match);
    return normalizeIP(entry.match) === normalizedIp;
  });
  return override ? override.country : null;
}

function getCountry(req) {
  const ip = getIP(req);
  if (!ip || ip === '::1' || ip === '127.0.0.1' || ip.startsWith('192.168.') || ip.startsWith('10.')) return null;
  const override = countryOverrideForIP(ip);
  if (override) return override;
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

function requireModerator(req, res, next) {
  const role = req.session.staff && req.session.staff.role;
  if (role !== 'admin' && role !== 'moderator') {
    return res.status(403).json({ error: 'Moderators only' });
  }
  next();
}

function canModerateBoard(staff, boardSlug, cb) {
  if (!staff) return cb(false);
  if (staff.role === 'admin' || staff.role === 'moderator') return cb(true);
  if (staff.role !== 'janitor' || !boardSlug) return cb(false);
  db.get(
    'SELECT 1 FROM staff_boards WHERE staff_id = ? AND board_slug = ?',
    [staff.id, boardSlug],
    (err, row) => cb(Boolean(!err && row))
  );
}

function requireBoardStaffFromPost(req, res, next) {
  db.get(
    `SELECT p.*, t.board_slug FROM posts p
     JOIN threads t ON t.id = p.thread_id
     WHERE p.id = ?`,
    [req.params.id],
    (err, post) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!post) return res.status(404).json({ error: 'Post not found' });
      canModerateBoard(req.session.staff, post.board_slug, allowed => {
        if (!allowed) return res.status(403).json({ error: 'You are not assigned to this board' });
        req.targetPost = post;
        next();
      });
    }
  );
}

function requireBoardStaffFromThread(req, res, next) {
  db.get('SELECT * FROM threads WHERE id = ?', [req.params.id], (err, thread) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!thread) return res.status(404).json({ error: 'Thread not found' });
    canModerateBoard(req.session.staff, thread.board_slug, allowed => {
      if (!allowed) return res.status(403).json({ error: 'You are not assigned to this board' });
      req.targetThread = thread;
      next();
    });
  });
}

function requireBoardStaffFromReport(req, res, next) {
  db.get('SELECT * FROM reports WHERE id = ?', [req.params.id], (err, report) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!report) return res.status(404).json({ error: 'Report not found' });
    canModerateBoard(req.session.staff, report.board_slug, allowed => {
      if (!allowed) return res.status(403).json({ error: 'You are not assigned to this board' });
      req.targetReport = report;
      next();
    });
  });
}

function ensureCsrfToken(req) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  return req.session.csrfToken;
}

function requireCsrf(req, res, next) {
  const expected = ensureCsrfToken(req);
  const received = req.headers['csrf-token'] || req.headers['x-csrf-token'];
  if (!received || received !== expected) {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  next();
}

function banAppliesToBoard(ban, boardSlug) {
  const scope = ban.ban_scope || 'all';
  return scope === 'all' || (scope === 'board' && ban.ban_board === boardSlug);
}

function getRequestBoardSlug(req, cb) {
  if (req.params.slug) return cb(null, req.params.slug);
  if (req.params.id) {
    return db.get('SELECT board_slug FROM threads WHERE id = ?', [req.params.id], (err, thread) => {
      if (err) return cb(err);
      cb(null, thread ? thread.board_slug : null);
    });
  }
  cb(null, req.query.board || req.body.board_slug || null);
}

async function checkBan(req, res, next) {
  const ip = getIP(req);
  getRequestBoardSlug(req, (boardErr, boardSlug) => {
    if (boardErr) return res.status(500).json({ error: boardErr.message });
    db.all(
      `SELECT * FROM bans
       WHERE expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP`,
      (err, bans) => {
      if (err) return res.status(500).json({ error: err.message });
      const ban = (bans || []).find(row => banAppliesToIP(row.ip_address, ip) && banAppliesToBoard(row, boardSlug));
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
  });
}

function logAction(staffUsername, action, targetId, note) {
  db.run(
    'INSERT INTO mod_log (staff_username, action, target_id, note) VALUES (?, ?, ?, ?)',
    [staffUsername, action, targetId, note]
  );
}

function makeCaptcha() {
  const templates = [
    () => {
      const a = 12 + Math.floor(Math.random() * 18);
      const b = 3 + Math.floor(Math.random() * 9);
      const c = 2 + Math.floor(Math.random() * 5);
      return {
        question: `What is ${a} + ${b} - ${c}?`,
        answer: String(a + b - c)
      };
    },
    () => {
      const words = ['saffron', 'lotus', 'monsoon', 'mango', 'river', 'cobalt'];
      const word = words[Math.floor(Math.random() * words.length)];
      return {
        question: `Type the third letter of "${word}" followed by the number of letters in it.`,
        answer: `${word[2]}${word.length}`
      };
    },
    () => {
      const start = 4 + Math.floor(Math.random() * 8);
      const step = 2 + Math.floor(Math.random() * 4);
      return {
        question: `Complete the pattern: ${start}, ${start + step}, ${start + step * 2}, __`,
        answer: String(start + step * 3)
      };
    },
    () => {
      const colors = ['green', 'blue', 'orange', 'white', 'red'];
      const target = colors[Math.floor(Math.random() * colors.length)];
      return {
        question: `Type the word "${target}" backwards.`,
        answer: target.split('').reverse().join('')
      };
    }
  ];
  return templates[Math.floor(Math.random() * templates.length)]();
}

function setCaptcha(req) {
  const captcha = makeCaptcha();
  req.session.captchaAnswer = captcha.answer.toLowerCase();
  return { question: captcha.question };
}

function requireCaptcha(req, res, next) {
  const expected = req.session.captchaAnswer;
  const received = String(req.body.captcha_answer || '').trim().toLowerCase();
  if (!expected || received !== expected) {
    if (req.file) fs.remove(path.join('uploads', req.file.filename), () => {});
    setCaptcha(req);
    return res.status(400).json({ error: 'Captcha answer is incorrect.', captchaRequired: true });
  }
  delete req.session.captchaAnswer;
  next();
}

// ─── Public API ───────────────────────────────────────────────

app.get('/api/boards', (req, res) => {
  db.all('SELECT * FROM boards', (err, rows) => res.json(rows || []));
});

app.get('/api/captcha', (req, res) => {
  res.json(setCaptcha(req));
});

app.get('/api/boards/:slug/threads', (req, res) => {
  db.all(
    `SELECT t.*, p.content, p.image_path, p.poster_name, p.tripcode, p.staff_role, p.staff_name, p.image_mature FROM threads t
     JOIN posts p ON p.id = (
       SELECT id FROM posts WHERE thread_id = t.id AND deleted = 0 ORDER BY id LIMIT 1
     )
     WHERE t.board_slug = ? ORDER BY t.pinned DESC, t.bumped_at DESC LIMIT 50`,
    [req.params.slug], (err, rows) => {
      if (!rows || !rows.length) return res.json([]);
      let done = 0;
      rows.forEach(thread => {
        db.all(
          `SELECT id, thread_id, content, image_path, country, poster_name, tripcode, staff_role, staff_name, image_mature, created_at
           FROM posts WHERE thread_id = ? AND deleted = 0 ORDER BY id DESC LIMIT 3`,
          [thread.id], (err, replies) => {
            thread.preview_replies = replies ? replies.reverse() : [];
            done++;
            if (done === rows.length) res.json(rows);
          }
        );
      });
    }
  );
});

app.get('/api/boards/:slug/catalog', (req, res) => {
  db.all(
    `SELECT
       t.id, t.board_slug, t.subject, t.pinned, t.locked, t.created_at, t.bumped_at,
       p.content, p.image_path, p.image_mature,
       (
         SELECT COUNT(*) - 1 FROM posts
         WHERE thread_id = t.id AND deleted = 0
       ) AS reply_count,
       (
         SELECT COUNT(*) FROM posts
         WHERE thread_id = t.id AND deleted = 0 AND image_path IS NOT NULL
       ) AS image_count
     FROM threads t
     JOIN posts p ON p.id = (
       SELECT id FROM posts WHERE thread_id = t.id AND deleted = 0 ORDER BY id LIMIT 1
     )
     WHERE t.board_slug = ?
     ORDER BY t.pinned DESC, t.bumped_at DESC
     LIMIT 120`,
    [req.params.slug],
    (err, rows) => res.json(rows || [])
  );
});

app.get('/api/recent-posts', (req, res) => {
  db.all(
    `SELECT
       p.id, p.thread_id, p.content, p.image_path, p.image_mature, p.created_at,
       t.board_slug, t.subject
     FROM posts p
     JOIN threads t ON t.id = p.thread_id
     WHERE p.deleted = 0
     ORDER BY p.created_at DESC
     LIMIT 20`,
    (err, rows) => res.json(rows || [])
  );
});

app.get('/api/search', (req, res) => {
  const q = String(req.query.q || '').trim();
  const board = String(req.query.board || '').trim();
  if (q.length < 2) return res.json([]);

  const params = [`%${escapeLike(q)}%`];
  let boardFilter = '';
  if (board) {
    boardFilter = 'AND t.board_slug = ?';
    params.push(board);
  }

  db.all(
    `SELECT
       p.id, p.thread_id, p.content, p.image_path, p.image_mature, p.created_at,
       t.board_slug, t.subject
     FROM posts p
     JOIN threads t ON t.id = p.thread_id
     WHERE p.deleted = 0
       AND (p.content LIKE ? ESCAPE '\\' OR t.subject LIKE ? ESCAPE '\\')
       ${boardFilter}
     ORDER BY p.created_at DESC
     LIMIT 50`,
    [params[0], ...params],
    (err, rows) => res.json(rows || [])
  );
});

app.get('/api/posts/lookup', (req, res) => {
  const ids = parseIdList(req.query.ids);
  if (!ids.length) return res.json([]);

  db.all(
    `SELECT
       p.id, p.thread_id, p.content, p.image_path, p.image_mature, p.created_at,
       p.poster_name, p.tripcode, p.staff_role, p.staff_name,
       t.board_slug, t.subject
     FROM posts p
     JOIN threads t ON t.id = p.thread_id
     WHERE p.deleted = 0 AND p.id IN (${ids.map(() => '?').join(',')})
     ORDER BY p.created_at DESC`,
    ids,
    (err, rows) => res.json(rows || [])
  );
});

app.get('/api/threads/lookup', (req, res) => {
  const ids = parseIdList(req.query.ids);
  if (!ids.length) return res.json([]);

  db.all(
    `SELECT
       t.id, t.board_slug, t.subject, t.pinned, t.locked, t.created_at, t.bumped_at,
       p.content, p.image_path, p.image_mature,
       (
         SELECT COUNT(*) - 1 FROM posts
         WHERE thread_id = t.id AND deleted = 0
       ) AS reply_count
     FROM threads t
     JOIN posts p ON p.id = (
       SELECT id FROM posts WHERE thread_id = t.id AND deleted = 0 ORDER BY id LIMIT 1
     )
     WHERE t.id IN (${ids.map(() => '?').join(',')})
     ORDER BY t.bumped_at DESC`,
    ids,
    (err, rows) => res.json(rows || [])
  );
});

app.post('/api/boards/:slug/threads', checkBan, upload.single('image'), requireCaptcha, (req, res) => {
  const { subject, content } = req.body;
  const identity = parsePosterIdentity(req.body.poster_name);
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
        'INSERT INTO posts (thread_id, content, image_path, ip_address, country, poster_name, tripcode, staff_role, staff_name, image_mature, delete_password) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [threadId, content, image_path, ip, country, identity.posterName, identity.tripcode, staff_role, staff_name, image_mature, delete_password],
        function(err) {
          if (err) return res.status(500).json({ error: err.message });
          res.json({ threadId, postId: this.lastID });
        }
      );
    }
  );
});

app.get('/api/threads/:id/posts', (req, res) => {
  db.all(
    `SELECT id, thread_id, content, image_path, country, poster_name, tripcode, staff_role, staff_name, image_mature, down_reply, created_at
     FROM posts WHERE thread_id = ? AND deleted = 0 ORDER BY id`,
    [req.params.id], (err, rows) => res.json(rows || [])
  );
});

app.get('/api/threads/:id/info', (req, res) => {
  db.get('SELECT * FROM threads WHERE id = ?', [req.params.id], (err, thread) => {
    if (!thread) return res.status(404).json({ error: 'Thread not found' });
    res.json(thread);
  });
});

app.post('/api/threads/:id/posts', checkBan, upload.single('image'), requireCaptcha, (req, res) => {
  const { content } = req.body;
  const identity = parsePosterIdentity(req.body.poster_name);
  const image_path = req.file ? req.file.filename : null;
  const ip = getIP(req);
  const country = getCountry(req);
  const staff_role = req.session.staff ? req.session.staff.role : null;
  const staff_name = req.session.staff ? req.session.staff.username : null;
  const image_mature = req.body.image_mature === '1' ? 1 : 0;
  const down_reply = req.body.down_reply === '1' ? 1 : 0;
  const delete_password = req.body.delete_password || null;
  if (!content) return res.status(400).json({ error: 'Content required' });

  db.get('SELECT * FROM threads WHERE id = ?', [req.params.id], (err, thread) => {
    if (!thread) return res.status(404).json({ error: 'Thread not found' });
    if (thread.locked && !req.session.staff)
      return res.status(403).json({ error: 'This thread is locked.' });

    db.run(
      'INSERT INTO posts (thread_id, content, image_path, ip_address, country, poster_name, tripcode, staff_role, staff_name, image_mature, down_reply, delete_password) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [req.params.id, content, image_path, ip, country, identity.posterName, identity.tripcode, staff_role, staff_name, image_mature, down_reply, delete_password],
      function(err) {
        if (err) return res.status(500).json({ error: err.message });
        if (!down_reply) db.run('UPDATE threads SET bumped_at = CURRENT_TIMESTAMP WHERE id = ?', [req.params.id]);
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
    res.json({ id: staff.id, username: staff.username, role: staff.role });
  });
});

app.post('/api/staff/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/staff/me', (req, res) => {
  if (!req.session.staff) return res.status(401).json({ error: 'Not logged in' });
  res.json(req.session.staff);
});

app.get('/api/csrf-token', requireStaff, (req, res) => {
  res.json({ csrfToken: ensureCsrfToken(req) });
});

// ─── Mod Actions ─────────────────────────────────────────────

// MUST be before /api/mod/posts/:id
app.delete('/api/mod/posts/by-ip/:ip', requireModerator, requireCsrf, (req, res) => {
  const ip = req.params.ip;
  db.run('UPDATE posts SET deleted = 1 WHERE ip_address = ?', [ip], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    logAction(req.session.staff.username, 'delete_all_by_ip', null, `Deleted all posts by IP ${ip}`);
    res.json({ ok: true, deleted: this.changes });
  });
});

app.delete('/api/mod/posts/:id', requireStaff, requireCsrf, requireBoardStaffFromPost, (req, res) => {
  db.run('UPDATE posts SET deleted = 1 WHERE id = ?', [req.params.id], () => {
    logAction(req.session.staff.username, 'delete_post', req.params.id, null);
    res.json({ ok: true });
  });
});

app.delete('/api/mod/posts/:id/image', requireStaff, requireCsrf, requireBoardStaffFromPost, (req, res) => {
  const post = req.targetPost;
  if (!post.image_path) return res.status(404).json({ error: 'No image found' });
  fs.remove(path.join('uploads', post.image_path), () => {
    db.run('UPDATE posts SET image_path = NULL WHERE id = ?', [req.params.id], () => {
      logAction(req.session.staff.username, 'delete_image', req.params.id, null);
      res.json({ ok: true });
    });
  });
});

app.post('/api/mod/posts/:id/mature', requireStaff, requireCsrf, requireBoardStaffFromPost, (req, res) => {
  const post = req.targetPost;
  const newVal = post.image_mature ? 0 : 1;
  db.run('UPDATE posts SET image_mature = ? WHERE id = ?', [newVal, req.params.id], () => {
    logAction(req.session.staff.username, newVal ? 'mark_mature' : 'unmark_mature', req.params.id, null);
    res.json({ ok: true, mature: newVal });
  });
});

app.delete('/api/mod/threads/:id', requireModerator, requireCsrf, requireBoardStaffFromThread, (req, res) => {
  db.run('UPDATE posts SET deleted = 1 WHERE thread_id = ?', [req.params.id], () => {
    db.run('DELETE FROM threads WHERE id = ?', [req.params.id], () => {
      logAction(req.session.staff.username, 'delete_thread', req.params.id, null);
      res.json({ ok: true });
    });
  });
});

app.post('/api/mod/threads/:id/pin', requireModerator, requireCsrf, requireBoardStaffFromThread, (req, res) => {
  const thread = req.targetThread;
  const newVal = thread.pinned ? 0 : 1;
  db.run('UPDATE threads SET pinned = ? WHERE id = ?', [newVal, req.params.id], () => {
    logAction(req.session.staff.username, newVal ? 'pin_thread' : 'unpin_thread', req.params.id, null);
    res.json({ ok: true, pinned: newVal });
  });
});

app.post('/api/mod/threads/:id/lock', requireModerator, requireCsrf, requireBoardStaffFromThread, (req, res) => {
  const thread = req.targetThread;
  const newVal = thread.locked ? 0 : 1;
  db.run('UPDATE threads SET locked = ? WHERE id = ?', [newVal, req.params.id], () => {
    logAction(req.session.staff.username, newVal ? 'lock_thread' : 'unlock_thread', req.params.id, null);
    res.json({ ok: true, locked: newVal });
  });
});

app.post('/api/mod/ban', requireModerator, requireCsrf, (req, res) => {
  const { post_id, reason, duration_hours, ban_scope } = req.body;
  db.get(
    `SELECT p.*, t.board_slug FROM posts p
     JOIN threads t ON t.id = p.thread_id
     WHERE p.id = ?`,
    [post_id],
    (err, post) => {
    if (!post) return res.status(404).json({ error: 'Post not found' });
    const cleanScope = ban_scope === 'board' ? 'board' : 'all';
    const banBoard = cleanScope === 'board' ? post.board_slug : null;
    const expires = duration_hours
      ? new Date(Date.now() + duration_hours * 3600000).toISOString()
      : null;
    db.run(
      `INSERT INTO bans
       (ip_address, reason, banned_by, expires_at, post_id, post_content, post_image, ban_scope, ban_board)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [post.ip_address, reason, req.session.staff.username, expires, post.id, post.content, post.image_path, cleanScope, banBoard],
      function() {
        logAction(req.session.staff.username, 'ban', post_id, `${cleanScope === 'board' ? `Board ban /${banBoard}/` : 'Global ban'}. Reason: ${reason}`);
        res.json({ ok: true });
      }
    );
  });
});

app.delete('/api/mod/bans/:id', requireModerator, requireCsrf, (req, res) => {
  db.run('DELETE FROM bans WHERE id = ?', [req.params.id], () => {
    logAction(req.session.staff.username, 'unban', req.params.id, null);
    res.json({ ok: true });
  });
});

// ─── Admin Only ───────────────────────────────────────────────

app.post('/api/admin/staff', requireAdmin, requireCsrf, async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (!['admin', 'moderator', 'janitor'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }
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
  db.all('SELECT id, username, role, created_at FROM staff', (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!rows || !rows.length) return res.json([]);
    db.all('SELECT staff_id, board_slug FROM staff_boards', (boardErr, assignments) => {
      if (boardErr) return res.status(500).json({ error: boardErr.message });
      const byStaff = {};
      (assignments || []).forEach(row => {
        if (!byStaff[row.staff_id]) byStaff[row.staff_id] = [];
        byStaff[row.staff_id].push(row.board_slug);
      });
      res.json(rows.map(row => ({ ...row, boards: byStaff[row.id] || [] })));
    });
  });
});

app.put('/api/admin/staff/:id/boards', requireAdmin, requireCsrf, (req, res) => {
  const staffId = Number(req.params.id);
  const boards = Array.isArray(req.body.boards)
    ? req.body.boards.map(slug => String(slug).trim().toLowerCase()).filter(Boolean)
    : [];
  db.get('SELECT * FROM staff WHERE id = ?', [staffId], (err, staff) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!staff) return res.status(404).json({ error: 'Staff account not found' });
    if (staff.role !== 'janitor') return res.status(400).json({ error: 'Board assignments only apply to janitors' });
    db.serialize(() => {
      db.run('DELETE FROM staff_boards WHERE staff_id = ?', [staffId]);
      const stmt = db.prepare('INSERT OR IGNORE INTO staff_boards (staff_id, board_slug) VALUES (?, ?)');
      boards.forEach(slug => stmt.run(staffId, slug));
      stmt.finalize(err => {
        if (err) return res.status(500).json({ error: err.message });
        logAction(req.session.staff.username, 'set_staff_boards', staffId, boards.length ? boards.join(', ') : 'none');
        res.json({ ok: true, boards });
      });
    });
  });
});

app.delete('/api/admin/staff/:id', requireAdmin, requireCsrf, (req, res) => {
  const staffId = Number(req.params.id);
  if (staffId === req.session.staff.id) {
    return res.status(400).json({ error: 'You cannot remove your own account while logged in' });
  }
  db.get('SELECT * FROM staff WHERE id = ?', [staffId], (err, staff) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!staff) return res.status(404).json({ error: 'Staff account not found' });
    if (staff.role !== 'admin') {
      return db.serialize(() => {
        db.run('DELETE FROM staff_boards WHERE staff_id = ?', [staffId]);
        db.run('DELETE FROM staff WHERE id = ?', [staffId], () => res.json({ ok: true }));
      });
    }
    db.get(`SELECT COUNT(*) as count FROM staff WHERE role = 'admin'`, (countErr, row) => {
      if (countErr) return res.status(500).json({ error: countErr.message });
      if (row.count <= 1) return res.status(400).json({ error: 'You cannot remove the last admin account' });
      db.serialize(() => {
        db.run('DELETE FROM staff_boards WHERE staff_id = ?', [staffId]);
        db.run('DELETE FROM staff WHERE id = ?', [staffId], () => res.json({ ok: true }));
      });
    });
  });
});

app.post('/api/mod/posts/:id/ban-request', requireStaff, requireCsrf, requireBoardStaffFromPost, (req, res) => {
  const reason = String(req.body.reason || '').trim();
  if (!reason) return res.status(400).json({ error: 'Reason is required' });
  const post = req.targetPost;
  db.run(
    `INSERT INTO ban_requests (post_id, thread_id, board_slug, requested_by, reason)
     VALUES (?, ?, ?, ?, ?)`,
    [post.id, post.thread_id, post.board_slug, req.session.staff.username, reason],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      logAction(req.session.staff.username, 'request_ban', post.id, reason);
      res.json({ ok: true, id: this.lastID });
    }
  );
});

app.post('/api/staff/password', requireStaff, requireCsrf, async (req, res) => {
  const { current_password, new_password } = req.body;
  if (!current_password || !new_password) {
    return res.status(400).json({ error: 'Current password and new password are required' });
  }
  if (String(new_password).length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters' });
  }
  db.get('SELECT * FROM staff WHERE id = ?', [req.session.staff.id], async (err, staff) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!staff) return res.status(404).json({ error: 'Staff account not found' });
    const match = await bcrypt.compare(current_password, staff.password);
    if (!match) return res.status(403).json({ error: 'Current password is incorrect' });
    const hash = await bcrypt.hash(new_password, 10);
    db.run('UPDATE staff SET password = ? WHERE id = ?', [hash, staff.id], updateErr => {
      if (updateErr) return res.status(500).json({ error: updateErr.message });
      logAction(req.session.staff.username, 'change_password', staff.id, null);
      res.json({ ok: true });
    });
  });
});

app.get('/api/admin/bans', requireModerator, (req, res) => {
  db.all('SELECT * FROM bans ORDER BY created_at DESC', (err, rows) => res.json(rows));
});

app.get('/api/admin/log', requireAdmin, (req, res) => {
  db.all('SELECT * FROM mod_log ORDER BY created_at DESC LIMIT 200', (err, rows) => res.json(rows));
});

app.delete('/api/admin/log', requireAdmin, requireCsrf, (req, res) => {
  db.run('DELETE FROM mod_log', function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ ok: true, deleted: this.changes });
  });
});

app.post('/api/admin/log/prune', requireAdmin, requireCsrf, (req, res) => {
  const keep = Math.max(10, Math.min(Number(req.body.keep) || 200, 1000));
  db.run(
    `DELETE FROM mod_log
     WHERE id NOT IN (
       SELECT id FROM mod_log ORDER BY created_at DESC LIMIT ?
     )`,
    [keep],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      logAction(req.session.staff.username, 'prune_mod_log', null, `Kept newest ${keep} log entries`);
      res.json({ ok: true, deleted: this.changes, kept: keep });
    }
  );
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
  const boardFilter = req.session.staff.role === 'janitor'
    ? `AND t.board_slug IN (SELECT board_slug FROM staff_boards WHERE staff_id = ?)`
    : '';
  const params = req.session.staff.role === 'janitor' ? [req.session.staff.id] : [];
  db.all(
    `SELECT p.*, t.board_slug FROM posts p
     JOIN threads t ON t.id = p.thread_id
     WHERE p.deleted = 0 ${boardFilter}
     ORDER BY p.created_at DESC LIMIT 100`,
    params,
    (err, rows) => res.json(rows || [])
  );
});

app.get('/api/mod/deleted-posts', requireStaff, (req, res) => {
  const boardFilter = req.session.staff.role === 'janitor'
    ? `AND t.board_slug IN (SELECT board_slug FROM staff_boards WHERE staff_id = ?)`
    : '';
  const params = req.session.staff.role === 'janitor' ? [req.session.staff.id] : [];
  db.all(
    `SELECT p.*, t.board_slug FROM posts p
     LEFT JOIN threads t ON t.id = p.thread_id
     WHERE p.deleted = 1 ${boardFilter}
     ORDER BY p.created_at DESC LIMIT 100`,
    params,
    (err, rows) => res.json(rows || [])
  );
});

app.get('/api/mod/threads/:id/posts', requireStaff, (req, res) => {
  db.get('SELECT * FROM threads WHERE id = ?', [req.params.id], (err, thread) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!thread) return res.status(404).json({ error: 'Thread not found' });
    canModerateBoard(req.session.staff, thread.board_slug, allowed => {
      if (!allowed) return res.status(403).json({ error: 'You are not assigned to this board' });
      db.all(
        `SELECT p.*, t.board_slug FROM posts p
         JOIN threads t ON t.id = p.thread_id
         WHERE p.thread_id = ? AND p.deleted = 0
         ORDER BY p.id`,
        [req.params.id],
        (postErr, rows) => {
          if (postErr) return res.status(500).json({ error: postErr.message });
          res.json(rows || []);
        }
      );
    });
  });
});

app.post('/api/mod/posts/:id/restore', requireModerator, requireCsrf, (req, res) => {
  db.run('UPDATE posts SET deleted = 0 WHERE id = ?', [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ error: 'Post not found' });
    logAction(req.session.staff.username, 'restore_post', req.params.id, null);
    res.json({ ok: true });
  });
});

app.delete('/api/admin/posts/:id/hard', requireAdmin, requireCsrf, (req, res) => {
  db.get('SELECT * FROM posts WHERE id = ?', [req.params.id], (err, post) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!post) return res.status(404).json({ error: 'Post not found' });
    if (!post.deleted) return res.status(400).json({ error: 'Soft-delete the post before permanent deletion' });

    const removeImage = post.image_path
      ? fs.remove(path.join('uploads', post.image_path))
      : Promise.resolve();

    removeImage.finally(() => {
      db.serialize(() => {
        db.run(
          'UPDATE bans SET post_id = NULL, post_content = NULL, post_image = NULL WHERE post_id = ?',
          [post.id]
        );
        db.run('DELETE FROM reports WHERE post_id = ?', [post.id]);
        db.run('DELETE FROM posts WHERE id = ?', [post.id], function(deleteErr) {
          if (deleteErr) return res.status(500).json({ error: deleteErr.message });
          logAction(req.session.staff.username, 'hard_delete_post', post.id, 'Permanently deleted post and removed stored image/reference data');
          res.json({ ok: true });
        });
      });
    });
  });
});

app.post('/api/admin/posts/:id/emergency-remove', requireAdmin, requireCsrf, (req, res) => {
  const { reason, notes } = req.body;
  const cleanReason = String(reason || '').trim();
  if (!cleanReason) return res.status(400).json({ error: 'Reason is required' });

  db.get(
    `SELECT p.*, t.board_slug FROM posts p
     LEFT JOIN threads t ON t.id = p.thread_id
     WHERE p.id = ?`,
    [req.params.id],
    (err, post) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!post) return res.status(404).json({ error: 'Post not found' });

      const originalImagePath = post.image_path || null;
      const removeImage = originalImagePath
        ? fs.remove(path.join('uploads', originalImagePath))
        : Promise.resolve();

      removeImage.finally(() => {
        db.serialize(() => {
          db.run(
            `INSERT INTO legal_incidents
             (post_id, thread_id, board_slug, ip_address, image_path, reason, notes, action_taken, created_by)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
              post.id,
              post.thread_id,
              post.board_slug || null,
              post.ip_address || null,
              originalImagePath,
              cleanReason,
              notes ? String(notes).trim() : null,
              'soft_deleted_and_image_removed',
              req.session.staff.username
            ]
          );
          db.run(
            'UPDATE bans SET post_content = NULL, post_image = NULL WHERE post_id = ?',
            [post.id]
          );
          db.run(
            'UPDATE posts SET deleted = 1, image_path = NULL, content = ? WHERE id = ?',
            ['[removed by administrator]', post.id],
            function(updateErr) {
              if (updateErr) return res.status(500).json({ error: updateErr.message });
              logAction(req.session.staff.username, 'emergency_remove_post', post.id, cleanReason);
              res.json({ ok: true });
            }
          );
        });
      });
    }
  );
});

app.get('/api/admin/legal-incidents', requireAdmin, (req, res) => {
  db.all(
    'SELECT * FROM legal_incidents WHERE created_at >= ? ORDER BY created_at DESC LIMIT 200',
    [LEGAL_INCIDENTS_CLEAN_SLATE_AT],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows || []);
    }
  );
});

app.get('/api/ban-check', checkBan, (req, res) => res.json({ ok: true }));

app.post('/api/admin/boards', requireAdmin, requireCsrf, (req, res) => {
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

app.delete('/api/admin/boards/:slug', requireAdmin, requireCsrf, (req, res) => {
  db.serialize(() => {
    db.run('DELETE FROM staff_boards WHERE board_slug = ?', [req.params.slug]);
    db.run('DELETE FROM boards WHERE slug = ?', [req.params.slug], function(err) {
      if (this.changes === 0) return res.status(404).json({ error: 'Board not found' });
      logAction(req.session.staff.username, 'delete_board', null, `Deleted board /${req.params.slug}/`);
      res.json({ ok: true });
    });
  });
});

// ─── Reports ─────────────────────────────────────────────────

app.post('/api/reports', requireCaptcha, (req, res) => {
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
  const boardFilter = req.session.staff.role === 'janitor'
    ? `AND r.board_slug IN (SELECT board_slug FROM staff_boards WHERE staff_id = ?)`
    : '';
  const params = req.session.staff.role === 'janitor' ? [req.session.staff.id] : [];
  db.all(
    `SELECT r.*, p.content as post_content, p.image_path as post_image, p.ip_address as post_ip
     FROM reports r
     LEFT JOIN posts p ON p.id = r.post_id
     WHERE r.status = 'open' ${boardFilter}
     ORDER BY r.created_at DESC`,
    params,
    (err, rows) => res.json(rows || [])
  );
});

app.post('/api/mod/reports/:id/dismiss', requireStaff, requireCsrf, requireBoardStaffFromReport, (req, res) => {
  db.run(
    `UPDATE reports SET status = 'dismissed', resolved_by = ?, resolved_at = CURRENT_TIMESTAMP WHERE id = ?`,
    [req.session.staff.username, req.params.id],
    () => {
      logAction(req.session.staff.username, 'dismiss_report', req.params.id, null);
      res.json({ ok: true });
    }
  );
});

app.post('/api/mod/reports/:id/ban-reporter', requireModerator, requireCsrf, (req, res) => {
  const { reason, duration_hours, ban_scope } = req.body;
  db.get('SELECT * FROM reports WHERE id = ?', [req.params.id], (err, report) => {
    if (!report) return res.status(404).json({ error: 'Report not found' });
    const cleanScope = ban_scope === 'board' ? 'board' : 'all';
    const banBoard = cleanScope === 'board' ? report.board_slug : null;
    const expires = duration_hours ? new Date(Date.now() + duration_hours * 3600000).toISOString() : null;
    db.run(
      `INSERT INTO bans (ip_address, reason, banned_by, expires_at, ban_scope, ban_board)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [report.reporter_ip, reason || 'Abuse of report system', req.session.staff.username, expires, cleanScope, banBoard],
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

app.post('/api/mod/reports/:id/delete-post', requireStaff, requireCsrf, requireBoardStaffFromReport, (req, res) => {
  const report = req.targetReport;
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

app.post('/api/mod/reports/:id/ban-poster', requireModerator, requireCsrf, (req, res) => {
  const { reason, duration_hours, ban_scope } = req.body;
  db.get('SELECT * FROM reports WHERE id = ?', [req.params.id], (err, report) => {
    if (!report) return res.status(404).json({ error: 'Report not found' });
    db.get('SELECT * FROM posts WHERE id = ?', [report.post_id], (err, post) => {
      if (!post) return res.status(404).json({ error: 'Post not found' });
      const cleanScope = ban_scope === 'board' ? 'board' : 'all';
      const banBoard = cleanScope === 'board' ? report.board_slug : null;
      const expires = duration_hours ? new Date(Date.now() + duration_hours * 3600000).toISOString() : null;
      db.run('UPDATE posts SET deleted = 1 WHERE id = ?', [post.id], () => {
        db.run(
          `INSERT INTO bans (ip_address, reason, banned_by, expires_at, post_id, post_content, post_image, ban_scope, ban_board)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [post.ip_address, reason, req.session.staff.username, expires, post.id, post.content, post.image_path, cleanScope, banBoard],
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

app.get('/api/mod/ban-requests', requireModerator, (req, res) => {
  db.all(
    `SELECT br.*, p.content as post_content, p.image_path as post_image, p.ip_address as post_ip
     FROM ban_requests br
     LEFT JOIN posts p ON p.id = br.post_id
     WHERE br.status = 'open'
     ORDER BY br.created_at ASC`,
    (err, rows) => res.json(rows || [])
  );
});

app.post('/api/mod/ban-requests/:id/:action', requireModerator, requireCsrf, (req, res) => {
  const { action } = req.params;
  if (action !== 'accept' && action !== 'reject') return res.status(400).json({ error: 'Invalid action' });
  db.get(
    `SELECT br.*, p.content as post_content, p.image_path as post_image, p.ip_address as post_ip
     FROM ban_requests br
     LEFT JOIN posts p ON p.id = br.post_id
     WHERE br.id = ?`,
    [req.params.id],
    (err, request) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!request) return res.status(404).json({ error: 'Ban request not found' });
      if (request.status !== 'open') return res.status(400).json({ error: 'Ban request is already closed' });
      const finish = () => {
        db.run(
          `UPDATE ban_requests SET status = ?, resolved_by = ?, resolved_at = CURRENT_TIMESTAMP WHERE id = ?`,
          [action === 'accept' ? 'accepted' : 'rejected', req.session.staff.username, request.id],
          () => {
            logAction(req.session.staff.username, action === 'accept' ? 'accept_ban_request' : 'reject_ban_request', request.post_id, request.reason);
            res.json({ ok: true });
          }
        );
      };
      if (action === 'reject') return finish();
      if (!request.post_ip) return res.status(400).json({ error: 'Original post IP is unavailable' });
      const scope = req.body.ban_scope === 'all' ? 'all' : 'board';
      const banBoard = scope === 'board' ? request.board_slug : null;
      const duration = req.body.duration_hours;
      const expires = duration ? new Date(Date.now() + duration * 3600000).toISOString() : null;
      db.run(
        `INSERT INTO bans
         (ip_address, reason, banned_by, expires_at, post_id, post_content, post_image, ban_scope, ban_board)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [request.post_ip, request.reason, req.session.staff.username, expires, request.post_id, request.post_content, request.post_image, scope, banBoard],
        finish
      );
    }
  );
});
app.post('/api/appeals', requireCaptcha, (req, res) => {
  const ip = getIP(req);
  const { message, board_slug } = req.body;
  if (!message || !message.trim()) return res.status(400).json({ error: 'Appeal message required' });
  db.all(
    `SELECT * FROM bans WHERE expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP`,
    (err, bans) => {
      if (err) return res.status(500).json({ error: err.message });
      const ban = (bans || []).find(row => banAppliesToIP(row.ip_address, ip) && banAppliesToBoard(row, board_slug || null));
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

app.get('/api/mod/appeals', requireModerator, (req, res) => {
  db.all(
    `SELECT a.*, b.reason as ban_reason, b.expires_at, b.banned_by, b.post_content, b.post_image
     FROM appeals a
     JOIN bans b ON b.id = a.ban_id
     WHERE a.status = 'pending'
     ORDER BY a.created_at ASC`,
    (err, rows) => res.json(rows || [])
  );
});

app.post('/api/mod/appeals/:id/:action', requireModerator, requireCsrf, (req, res) => {
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
