require('dotenv').config();

const express = require('express');
const session = require('express-session');
const initSqlJs = require('sql.js');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { authenticator } = require('otplib');
const QRCode = require('qrcode');
const path = require('path');
const fs = require('fs');

const PORT = Number(process.env.PORT || 3000);
const BASE_URL = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const dataDir = path.join(__dirname, '..', 'data');
fs.mkdirSync(dataDir, { recursive: true });

async function main() {
const SQL = await initSqlJs();
const dbFile = path.join(dataDir, 'accounts.sqlite');
const rawDb = fs.existsSync(dbFile) ? new SQL.Database(fs.readFileSync(dbFile)) : new SQL.Database();
function persistDb() {
  fs.writeFileSync(dbFile, Buffer.from(rawDb.export()));
}
// Compatibility wrapper matching the subset of better-sqlite3 used by this app.
// sql.js is WebAssembly-based and does not require Visual Studio/C++ build tools.
const db = {
  pragma() {},
  exec(sql) { rawDb.exec(sql); persistDb(); },
  prepare(sql) {
    return {
      get(...params) {
        const stmt = rawDb.prepare(sql);
        try {
          stmt.bind(params);
          return stmt.step() ? stmt.getAsObject() : undefined;
        } finally { stmt.free(); }
      },
      all(...params) {
        const stmt = rawDb.prepare(sql);
        const rows = [];
        try {
          stmt.bind(params);
          while (stmt.step()) rows.push(stmt.getAsObject());
          return rows;
        } finally { stmt.free(); }
      },
      run(...params) {
        rawDb.run(sql, params);
        const changes = rawDb.getRowsModified();
        const resultStmt = rawDb.prepare('SELECT last_insert_rowid() AS id');
        let lastInsertRowid = 0;
        try { if (resultStmt.step()) lastInsertRowid = resultStmt.getAsObject().id || 0; }
        finally { resultStmt.free(); }
        persistDb();
        return { changes, lastInsertRowid };
      }
    };
  }
};
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  console.warn('WARNING: Set SESSION_SECRET to a random value of at least 32 characters in .env before using beyond local demo.');
}
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT,
  role TEXT NOT NULL DEFAULT 'user',
  active INTEGER NOT NULL DEFAULT 0,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER,
  twofa_enabled INTEGER NOT NULL DEFAULT 0,
  twofa_secret TEXT,
  google_id TEXT,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  type TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at INTEGER,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  email TEXT,
  event TEXT NOT NULL,
  ip TEXT,
  details TEXT,
  created_at INTEGER NOT NULL
);
`);
const app = express();

const now = () => Date.now();
const hashToken = token => crypto.createHash('sha256').update(token).digest('hex');
const randomToken = () => crypto.randomBytes(32).toString('hex');
const validPassword = p => typeof p === 'string' &&
  p.length >= 8 && /[a-z]/.test(p) && /[A-Z]/.test(p) && /\d/.test(p) && /[^A-Za-z0-9]/.test(p);
const escapeHtml = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const clientIp = req => (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').toString().split(',')[0].trim().slice(0, 80);

function logEvent(req, event, email = null, userId = null, details = '') {
  db.prepare('INSERT INTO audit_log (user_id,email,event,ip,details,created_at) VALUES (?,?,?,?,?,?)')
    .run(userId, email, event, clientIp(req), String(details).slice(0, 500), now());
}
function issueToken(userId, type, minutes) {
  const token = randomToken();
  db.prepare('INSERT INTO tokens (user_id,token_hash,type,expires_at,created_at) VALUES (?,?,?,?,?)')
    .run(userId, hashToken(token), type, now() + minutes * 60_000, now());
  return token;
}
function consumeToken(token, type) {
  if (!token || typeof token !== 'string') return null;
  const row = db.prepare(`SELECT * FROM tokens WHERE token_hash=? AND type=? AND used_at IS NULL AND expires_at>?`)
    .get(hashToken(token), type, now());
  if (!row) return null;
  db.prepare('UPDATE tokens SET used_at=? WHERE id=?').run(now(), row.id);
  return row;
}
function getUser(id) {
  return db.prepare('SELECT id,email,role,active,failed_attempts,locked_until,twofa_enabled,created_at FROM users WHERE id=?').get(id);
}
function currentUser(req) {
  if (!req.session.userId) return null;
  return getUser(req.session.userId) || null;
}
function requireAuth(req, res, next) {
  const user = currentUser(req);
  if (!user) return res.redirect('/login');
  req.user = user;
  next();
}
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') return res.status(403).send(page('Доступ заборонено', '<p>Ця сторінка доступна лише адміністратору.</p><p><a href="/">На головну</a></p>'));
  next();
}
function page(title, content, user = null, notice = '') {
  const nav = user
    ? `<a href="/profile">Профіль</a> ${user.role === 'admin' ? '<a href="/admin">Адміністрування</a>' : ''}<form class="inline" method="post" action="/logout"><button class="link" type="submit">Вийти</button></form>`
    : '<a href="/login">Вхід</a> <a href="/register">Реєстрація</a>';
  return `<!doctype html><html lang="uk"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${escapeHtml(title)}</title><link rel="stylesheet" href="/style.css"></head><body><header><a class="brand" href="/">Secure Accounts</a><nav>${nav}</nav></header><main><h1>${escapeHtml(title)}</h1>${notice ? `<div class="notice">${escapeHtml(notice)}</div>` : ''}${content}</main><footer>Навчальний проєкт · Не використовуйте реальні паролі</footer></body></html>`;
}
async function sendMail(to, subject, text) {
  const { SMTP_HOST, SMTP_PORT, SMTP_SECURE, SMTP_USER, SMTP_PASS, SMTP_FROM } = process.env;
  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS) {
    console.log(`\n[LOCAL DEMO EMAIL]\nTo: ${to}\nSubject: ${subject}\n${text}\n`);
    return false;
  }
  try {
    const transporter = nodemailer.createTransport({
      host: SMTP_HOST, port: Number(SMTP_PORT || 587), secure: String(SMTP_SECURE).toLowerCase() === 'true',
      auth: { user: SMTP_USER, pass: SMTP_PASS }
    });
    await transporter.sendMail({ from: SMTP_FROM || SMTP_USER, to, subject, text });
    return true;
  } catch (err) {
    console.error('Помилка відправки email:', err);
    return false;
  }
}
function renderFormError(message, user = null) {
  return page('Помилка', `<p class="error">${escapeHtml(message)}</p><p><a href="javascript:history.back()">Повернутися</a></p>`, user);
}

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: false, limit: '20kb' }));
app.use(express.static(path.join(__dirname, '..', 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'local-demo-secret-change-this-please-123456',
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 1000 * 60 * 60 * 4 }
}));
app.use(passport.initialize());
app.use(passport.session());

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false });
app.use(['/login', '/register', '/forgot'], authLimiter);

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => done(null, db.prepare('SELECT id,email,role,active,twofa_enabled FROM users WHERE id=?').get(id) || false));
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: `${BASE_URL}/auth/google/callback`
  }, (accessToken, refreshToken, profile, done) => {
    try {
      const email = profile.emails && profile.emails[0] && profile.emails[0].value;
      if (!email) return done(null, false);
      let user = db.prepare('SELECT * FROM users WHERE google_id=? OR email=?').get(profile.id, email.toLowerCase());
      if (user) {
        if (!user.google_id) db.prepare('UPDATE users SET google_id=?,active=1 WHERE id=?').run(profile.id, user.id);
      } else {
        const result = db.prepare('INSERT INTO users (email,role,active,google_id,created_at) VALUES (?,\'user\',1,?,?)')
          .run(email.toLowerCase(), profile.id, now());
        user = db.prepare('SELECT * FROM users WHERE id=?').get(result.lastInsertRowid);
      }
      return done(null, db.prepare('SELECT id,email,role,active,twofa_enabled FROM users WHERE id=?').get(user.id));
    } catch (e) { return done(e); }
  }));
}

app.get('/', (req, res) => {
  const user = currentUser(req);
  const content = `<p class="lead">Демонстраційна система безпечного керування обліковими записами.</p>
  <div class="grid"><section><h2>Захист акаунта</h2><p>Політика паролів, CAPTCHA, активація email, TOTP 2FA та відновлення доступу.</p></section>
  <section><h2>Адміністрування</h2><p>Рольовий доступ, журнал входів, блокування користувачів.</p></section></div>
  ${user ? `<p>Ви увійшли як <strong>${escapeHtml(user.email)}</strong>. <a href="/profile">Відкрити профіль</a></p>` : '<p><a class="button" href="/register">Створити акаунт</a> <a class="button secondary" href="/login">Увійти</a></p>'}`;
  res.send(page('Безпечне керування обліковими записами', content, user));
});

app.get('/register', (req, res) => {
  const a = crypto.randomInt(1, 10), b = crypto.randomInt(1, 10);
  req.session.captcha = { answer: String(a + b), at: now() };
  res.send(page('Реєстрація', `<form method="post" action="/register">
  <label>Email<input name="email" type="email" required maxlength="254" autocomplete="email"></label>
  <label>Пароль<input name="password" type="password" required autocomplete="new-password"><small>Мінімум 8 символів, великі й малі літери, цифра та спецсимвол.</small></label>
  <label>Повторіть пароль<input name="confirmPassword" type="password" required autocomplete="new-password"></label>
  <label>CAPTCHA: скільки буде ${a} + ${b}?<input name="captcha" inputmode="numeric" required></label>
  <button type="submit">Зареєструватися</button></form><p><a href="/login">Уже є акаунт?</a></p>`));
});
app.post('/register', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const confirm = String(req.body.confirmPassword || '');
  const captcha = req.session.captcha;
  delete req.session.captcha;
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) return res.status(400).send(renderFormError('Введіть коректну email-адресу.'));
  if (!validPassword(password)) return res.status(400).send(renderFormError('Пароль не відповідає політиці безпеки.'));
  if (password !== confirm) return res.status(400).send(renderFormError('Паролі не збігаються.'));
  if (!captcha || now() - captcha.at > 5 * 60_000 || String(req.body.captcha || '').trim() !== captcha.answer)
    return res.status(400).send(renderFormError('CAPTCHA неправильна або застаріла. Спробуйте ще раз.'));
  if (db.prepare('SELECT id FROM users WHERE email=?').get(email)) return res.status(409).send(renderFormError('Користувач із такою email-адресою вже існує.'));
  const passwordHash = await bcrypt.hash(password, 12);
  const result = db.prepare('INSERT INTO users (email,password_hash,role,active,created_at) VALUES (?,?,\'user\',0,?)').run(email, passwordHash, now());
  const token = issueToken(result.lastInsertRowid, 'activate', 30);
  logEvent(req, 'registration', email, result.lastInsertRowid, 'Акаунт створено; очікує активації');
  await sendMail(email, 'Активація облікового запису', `Відкрийте посилання протягом 30 хвилин: ${BASE_URL}/activate?token=${token}`);
  res.send(page('Перевірте пошту', `<p>Акаунт створено. Для локальної демонстрації посилання активації виведено в консоль сервера, якщо SMTP не налаштований.</p><p><a href="/login">Перейти до входу</a></p>`));
});
app.get('/activate', (req, res) => {
  const tokenRow = consumeToken(req.query.token, 'activate');
  if (!tokenRow) return res.status(400).send(renderFormError('Посилання активації недійсне, вже використане або прострочене.'));
  db.prepare('UPDATE users SET active=1 WHERE id=?').run(tokenRow.user_id);
  logEvent(req, 'account_activated', null, tokenRow.user_id);
  res.send(page('Акаунт активовано', '<p>Обліковий запис активовано. Тепер можна увійти.</p><p><a class="button" href="/login">Увійти</a></p>'));
});

app.get('/login', (req, res) => res.send(page('Вхід', `<form method="post" action="/login">
  <label>Email<input name="email" type="email" required autocomplete="username"></label>
  <label>Пароль<input name="password" type="password" required autocomplete="current-password"></label>
  <button type="submit">Увійти</button></form>
  ${process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET ? '<p><a class="button secondary" href="/auth/google">Увійти через Google</a></p>' : '<p class="muted">Google OAuth стане доступним після налаштування credentials у .env.</p>'}
  <p><a href="/forgot">Забули пароль?</a> · <a href="/register">Реєстрація</a></p>`)));
app.post('/login', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const user = db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if (!user) {
    logEvent(req, 'login_failed', email, null, 'Невірні облікові дані');
    return res.status(401).send(renderFormError('Невірний email або пароль.'));
  }
  if (user.locked_until && user.locked_until > now()) {
    logEvent(req, 'login_blocked', email, user.id, 'Акаунт тимчасово заблоковано');
    return res.status(423).send(renderFormError(`Акаунт тимчасово заблоковано. Спробуйте пізніше.`));
  }
  const matches = user.password_hash && await bcrypt.compare(password, user.password_hash);
  if (!matches) {
    const attempts = user.failed_attempts + 1;
    const lockedUntil = attempts >= 5 ? now() + 15 * 60_000 : null;
    db.prepare('UPDATE users SET failed_attempts=?,locked_until=? WHERE id=?').run(lockedUntil ? 0 : attempts, lockedUntil, user.id);
    logEvent(req, 'login_failed', email, user.id, `Невдала спроба; лічильник ${attempts}`);
    return res.status(401).send(renderFormError(lockedUntil ? 'Забагато невдалих спроб. Акаунт заблоковано на 15 хвилин.' : 'Невірний email або пароль.'));
  }
  if (!user.active) {
    logEvent(req, 'login_inactive', email, user.id);
    return res.status(403).send(renderFormError('Спочатку активуйте акаунт через email.'));
  }
  db.prepare('UPDATE users SET failed_attempts=0,locked_until=NULL WHERE id=?').run(user.id);
  logEvent(req, 'login_password_ok', email, user.id);
  if (user.twofa_enabled) {
    req.session.pending2faUserId = user.id;
    return res.redirect('/2fa/challenge');
  }
  req.session.regenerate(err => {
    if (err) return res.status(500).send(renderFormError('Не вдалося створити сесію.'));
    req.session.userId = user.id;
    logEvent(req, 'login_success', email, user.id);
    res.redirect('/profile');
  });
});
app.post('/logout', (req, res) => {
  const user = currentUser(req);
  if (user) logEvent(req, 'logout', user.email, user.id);
  req.session.destroy(() => res.redirect('/'));
});

app.get('/profile', requireAuth, (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
  res.send(page('Мій профіль', `<dl><dt>Email</dt><dd>${escapeHtml(u.email)}</dd><dt>Роль</dt><dd>${escapeHtml(u.role)}</dd><dt>Акаунт активовано</dt><dd>${u.active ? 'Так' : 'Ні'}</dd><dt>2FA</dt><dd>${u.twofa_enabled ? 'Увімкнено' : 'Вимкнено'}</dd><dt>Створено</dt><dd>${new Date(u.created_at).toLocaleString('uk-UA')}</dd></dl>
  <h2>Двофакторна автентифікація</h2>
  ${u.twofa_enabled ? `<form method="post" action="/2fa/disable"><label>Поточний код з автентифікатора<input name="code" inputmode="numeric" required></label><button class="danger" type="submit">Вимкнути 2FA</button></form>` : `<p>Увімкніть TOTP, щоб вимагати одноразовий код під час входу.</p><form method="post" action="/2fa/setup"><button type="submit">Налаштувати 2FA</button></form>`}
  <p><a href="/">На головну</a></p>`, req.user));
});

app.post('/2fa/setup', requireAuth, async (req, res) => {
  const secret = authenticator.generateSecret();
  db.prepare('UPDATE users SET twofa_secret=? WHERE id=?').run(secret, req.user.id);
  const otpauth = authenticator.keyuri(req.user.email, 'Secure Account Management', secret);
  const qr = await QRCode.toDataURL(otpauth);
  res.send(page('Налаштування 2FA', `<p>Відскануйте QR-код застосунком-аутентифікатором. Якщо сканування недоступне, введіть секрет вручну.</p><img class="qr" alt="QR-код для TOTP" src="${qr}"><p><code>${escapeHtml(secret)}</code></p><form method="post" action="/2fa/confirm"><label>Код із застосунку<input name="code" inputmode="numeric" required></label><button type="submit">Підтвердити та ввімкнути 2FA</button></form>`, req.user));
});
app.post('/2fa/confirm', requireAuth, (req, res) => {
  const u = db.prepare('SELECT twofa_secret FROM users WHERE id=?').get(req.user.id);
  if (!u.twofa_secret || !authenticator.check(String(req.body.code || ''), u.twofa_secret))
    return res.status(400).send(renderFormError('Неправильний код 2FA.', req.user));
  db.prepare('UPDATE users SET twofa_enabled=1 WHERE id=?').run(req.user.id);
  logEvent(req, '2fa_enabled', req.user.email, req.user.id);
  res.redirect('/profile');
});
app.post('/2fa/disable', requireAuth, (req, res) => {
  const u = db.prepare('SELECT twofa_secret FROM users WHERE id=?').get(req.user.id);
  if (!u.twofa_secret || !authenticator.check(String(req.body.code || ''), u.twofa_secret))
    return res.status(400).send(renderFormError('Неправильний код 2FA.', req.user));
  db.prepare('UPDATE users SET twofa_enabled=0,twofa_secret=NULL WHERE id=?').run(req.user.id);
  logEvent(req, '2fa_disabled', req.user.email, req.user.id);
  res.redirect('/profile');
});
app.get('/2fa/challenge', (req, res) => {
  if (!req.session.pending2faUserId) return res.redirect('/login');
  res.send(page('Підтвердження 2FA', `<form method="post" action="/2fa/challenge"><label>Одноразовий код<input name="code" inputmode="numeric" required autofocus></label><button type="submit">Підтвердити</button></form>`));
});
app.post('/2fa/challenge', (req, res) => {
  const id = req.session.pending2faUserId;
  const u = id && db.prepare('SELECT * FROM users WHERE id=?').get(id);
  if (!u || !u.twofa_enabled || !u.twofa_secret || !authenticator.check(String(req.body.code || ''), u.twofa_secret)) {
    logEvent(req, '2fa_failed', u ? u.email : null, id || null);
    return res.status(401).send(renderFormError('Неправильний код 2FA.'));
  }
  req.session.regenerate(err => {
    if (err) return res.status(500).send(renderFormError('Не вдалося створити сесію.'));
    req.session.userId = u.id;
    logEvent(req, 'login_success_2fa', u.email, u.id);
    res.redirect('/profile');
  });
});

app.get('/forgot', (req, res) => res.send(page('Відновлення пароля', `<p>Введіть email, на який зареєстровано акаунт.</p><form method="post" action="/forgot"><label>Email<input name="email" type="email" required></label><button type="submit">Надіслати посилання</button></form>`)));
app.post('/forgot', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const user = db.prepare('SELECT id,email FROM users WHERE email=?').get(email);
  if (user) {
    const token = issueToken(user.id, 'reset', 15);
    await sendMail(user.email, 'Відновлення пароля', `Посилання дійсне 15 хвилин: ${BASE_URL}/reset?token=${token}`);
    logEvent(req, 'password_reset_requested', user.email, user.id);
  }
  // Same response regardless of whether the email exists.
  res.send(page('Перевірте пошту', '<p>Якщо акаунт із такою адресою існує, інструкція для відновлення надіслана. Для локального демо перевірте консоль сервера.</p><p><a href="/login">До входу</a></p>'));
});
app.get('/reset', (req, res) => {
  const row = req.query.token && db.prepare('SELECT id FROM tokens WHERE token_hash=? AND type=\'reset\' AND used_at IS NULL AND expires_at>?').get(hashToken(String(req.query.token)), now());
  if (!row) return res.status(400).send(renderFormError('Токен відновлення недійсний або прострочений.'));
  res.send(page('Новий пароль', `<form method="post" action="/reset"><input type="hidden" name="token" value="${escapeHtml(req.query.token)}"><label>Новий пароль<input name="password" type="password" required autocomplete="new-password"></label><label>Повторіть пароль<input name="confirmPassword" type="password" required autocomplete="new-password"></label><button type="submit">Змінити пароль</button></form>`));
});
app.post('/reset', async (req, res) => {
  const token = String(req.body.token || '');
  const password = String(req.body.password || '');
  if (!validPassword(password)) return res.status(400).send(renderFormError('Пароль не відповідає політиці безпеки.'));
  if (password !== String(req.body.confirmPassword || '')) return res.status(400).send(renderFormError('Паролі не збігаються.'));
  const row = consumeToken(token, 'reset');
  if (!row) return res.status(400).send(renderFormError('Токен недійсний або вже використаний.'));
  const hash = await bcrypt.hash(password, 12);
  db.prepare('UPDATE users SET password_hash=?,failed_attempts=0,locked_until=NULL WHERE id=?').run(hash, row.user_id);
  db.prepare('UPDATE tokens SET used_at=? WHERE user_id=? AND type=\'reset\' AND used_at IS NULL').run(now(), row.user_id);
  logEvent(req, 'password_reset_completed', null, row.user_id);
  res.send(page('Пароль змінено', '<p>Пароль успішно змінено. Тепер можна увійти з новим паролем.</p><p><a class="button" href="/login">Увійти</a></p>'));
});

app.get('/auth/google', (req, res, next) => {
  if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET)
    return res.status(503).send(page('Google OAuth не налаштовано', '<p>Заповніть GOOGLE_CLIENT_ID і GOOGLE_CLIENT_SECRET у файлі .env та перезапустіть сервер.</p><p><a href="/login">Назад</a></p>'));
  passport.authenticate('google', { scope: ['profile', 'email'], session: false })(req, res, next);
});
app.get('/auth/google/callback', (req, res, next) => {
  if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) return res.redirect('/login');
  passport.authenticate('google', { failureRedirect: '/login', session: false }, (err, user) => {
    if (err || !user) return res.redirect('/login');
    req.session.regenerate(e => {
      if (e) return res.status(500).send(renderFormError('Не вдалося створити сесію.'));
      req.session.userId = user.id;
      logEvent(req, 'google_login_success', user.email, user.id);
      res.redirect('/profile');
    });
  })(req, res, next);
});

app.get('/admin', requireAuth, requireAdmin, (req, res) => {
  const users = db.prepare('SELECT id,email,role,active,failed_attempts,locked_until,twofa_enabled,created_at FROM users ORDER BY created_at DESC LIMIT 200').all();
  const logs = db.prepare('SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 100').all();
  const userRows = users.map(u => `<tr><td>${u.id}</td><td>${escapeHtml(u.email)}</td><td>${escapeHtml(u.role)}</td><td>${u.active ? 'Так' : 'Ні'}</td><td>${u.twofa_enabled ? 'Так' : 'Ні'}</td><td>${u.locked_until && u.locked_until > now() ? new Date(u.locked_until).toLocaleString('uk-UA') : 'Ні'}</td><td><form method="post" action="/admin/user/${u.id}/toggle-lock"><button class="small" type="submit">${u.locked_until && u.locked_until > now() ? 'Розблокувати' : 'Заблокувати'}</button></form></td></tr>`).join('');
  const logRows = logs.map(l => `<tr><td>${new Date(l.created_at).toLocaleString('uk-UA')}</td><td>${escapeHtml(l.email || '—')}</td><td>${escapeHtml(l.event)}</td><td>${escapeHtml(l.ip || '—')}</td><td>${escapeHtml(l.details || '')}</td></tr>`).join('');
  res.send(page('Панель адміністратора', `<h2>Користувачі</h2><div class="table-wrap"><table><thead><tr><th>ID</th><th>Email</th><th>Роль</th><th>Активний</th><th>2FA</th><th>Блокування до</th><th>Дія</th></tr></thead><tbody>${userRows || '<tr><td colspan="7">Немає користувачів</td></tr>'}</tbody></table></div>
  <h2>Журнал подій (останні 100)</h2><div class="table-wrap"><table><thead><tr><th>Час</th><th>Email</th><th>Подія</th><th>IP</th><th>Деталі</th></tr></thead><tbody>${logRows || '<tr><td colspan="5">Подій немає</td></tr>'}</tbody></table></div>`, req.user));
});
app.post('/admin/user/:id/toggle-lock', requireAuth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(id);
  if (!u) return res.status(404).send(renderFormError('Користувача не знайдено.', req.user));
  if (u.id === req.user.id) return res.status(400).send(renderFormError('Не можна змінити блокування власного адміністративного акаунта.', req.user));
  const isLocked = u.locked_until && u.locked_until > now();
  db.prepare('UPDATE users SET locked_until=?,failed_attempts=0 WHERE id=?').run(isLocked ? null : now() + 24 * 60 * 60_000, id);
  logEvent(req, isLocked ? 'admin_unlocked_user' : 'admin_locked_user', u.email, id, `Адміністратор ${req.user.email}`);
  res.redirect('/admin');
});

app.use((req, res) => res.status(404).send(page('Сторінку не знайдено', '<p>Перевірте адресу або поверніться на головну.</p><p><a href="/">На головну</a></p>', currentUser(req))));
app.use((err, req, res, next) => {
  console.error(err);
  if (res.headersSent) return next(err);
  res.status(500).send(page('Внутрішня помилка', '<p>Сталася помилка. Перевірте консоль сервера.</p>'));
});

const adminEmail = String(process.env.ADMIN_EMAIL || '').trim().toLowerCase();
const adminPassword = String(process.env.ADMIN_PASSWORD || '');
if (adminEmail && adminPassword && !db.prepare('SELECT id FROM users WHERE email=?').get(adminEmail)) {
  if (!validPassword(adminPassword)) {
    console.warn('ADMIN_PASSWORD does not meet password policy; initial admin was not created. Update .env.');
  } else {
    bcrypt.hash(adminPassword, 12).then(hash => {
      db.prepare('INSERT OR IGNORE INTO users (email,password_hash,role,active,created_at) VALUES (?,?,\'admin\',1,?)').run(adminEmail, hash, now());
      console.log(`Initial admin account ready: ${adminEmail}. Change its password after first login.`);
    });
  }
}
app.listen(PORT, () => console.log(`Secure Account Management running at ${BASE_URL}`));
}

main().catch(err => { console.error('Failed to start application:', err); process.exit(1); });
