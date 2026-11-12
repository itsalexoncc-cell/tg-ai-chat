const ALLOWED_ORIGIN = "https://itsalexoncc-cell.github.io";
const CORS_METHODS = "GET, POST, PUT, DELETE, OPTIONS";
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const sleep = ms => new Promise(r => setTimeout(r, ms));

function response(data, status = 200, origin = ALLOWED_ORIGIN) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": CORS_METHODS,
      "Access-Control-Allow-Headers": "Content-Type, X-Telegram-Init-Data",
      "Vary": "Origin"
    }
  });
}

function toBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(value) {
  return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}

function toHex(bytes) {
  return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
}

async function hmac(keyBytes, message) {
  const key = await crypto.subtle.importKey(
    "raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
}

/* Возвращает объект пользователя Telegram (с id) или null */
async function verifyTelegram(initData, botToken) {
  const params = new URLSearchParams(initData);
  const receivedHash = params.get("hash");
  const authDate = Number(params.get("auth_date"));
  const userText = params.get("user");

  if (!receivedHash || !authDate || !userText) return null;
  if (!Number.isFinite(authDate)) return null;

  const now = Math.floor(Date.now() / 1000);
  if (authDate > now + 60 || now - authDate > 86400) return null;

  params.delete("hash");

  const dataCheckString = [...params.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${value}`)
    .join("\n");

  const secretKey = await hmac(
    encoder.encode("WebAppData"),
    encoder.encode(botToken)
  );

  const calculatedHash = toHex(
    await hmac(secretKey, encoder.encode(dataCheckString))
  );

  if (calculatedHash.length !== receivedHash.length) return null;

  let difference = 0;
  for (let i = 0; i < calculatedHash.length; i++) {
    difference |= calculatedHash.charCodeAt(i) ^ receivedHash.charCodeAt(i);
  }
  if (difference !== 0) return null;

  try {
    const user = JSON.parse(userText);
    return user && user.id ? user : null;
  } catch {
    return null;
  }
}

async function authUser(request, env) {
  const initData = request.headers.get("X-Telegram-Init-Data");
  if (!initData) return { error: response({ error: "Telegram authentication required" }, 401) };
  const user = await verifyTelegram(initData, env.TELEGRAM_BOT_TOKEN);
  if (!user) return { error: response({ error: "Invalid or expired Telegram session" }, 401) };
  const userId = String(user.id);
  // администратор определяется только здесь: ADMIN_ID задаётся в настройках воркера
  const isAdmin = !!env.ADMIN_ID && userId === String(env.ADMIN_ID).trim();
  return { user, userId, isAdmin };
}

async function encryptionKey(secret) {
  const material = await crypto.subtle.importKey(
    "raw", encoder.encode(secret), "HKDF", false, ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: encoder.encode("tg-ai-chat-v1"),
      info: encoder.encode("api-key-encryption")
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptKey(value, secret) {
  const key = await encryptionKey(secret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoder.encode(value)
  );

  return {
    encrypted_key: toBase64(new Uint8Array(encrypted)),
    iv: toBase64(iv)
  };
}

async function decryptKey(encrypted, iv, secret) {
  const key = await encryptionKey(secret);
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64(iv) },
    key,
    fromBase64(encrypted)
  );
  return decoder.decode(decrypted);
}

function validProvider(provider) {
  return typeof provider === "string" &&
    /^[a-z0-9_-]{1,40}$/.test(provider);
}

/* ---------- схема БД (создаётся автоматически при первом обращении) ---------- */
let schemaReady = false;

async function ensureSchema(env) {
  if (schemaReady) return;
  await env.DB.batch([
    env.DB.prepare("CREATE TABLE IF NOT EXISTS app_config (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT DEFAULT CURRENT_TIMESTAMP)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS users (telegram_user_id TEXT PRIMARY KEY, first_name TEXT, username TEXT, language_code TEXT, blocked INTEGER NOT NULL DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP, last_seen TEXT DEFAULT CURRENT_TIMESTAMP)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS broadcasts (id TEXT PRIMARY KEY, client_token TEXT UNIQUE, title TEXT NOT NULL DEFAULT '', text TEXT NOT NULL DEFAULT '', media TEXT NOT NULL DEFAULT '[]', status TEXT NOT NULL DEFAULT 'sending', total INTEGER NOT NULL DEFAULT 0, sent INTEGER NOT NULL DEFAULT 0, failed INTEGER NOT NULL DEFAULT 0, blocked INTEGER NOT NULL DEFAULT 0, lock_until INTEGER NOT NULL DEFAULT 0, last_error TEXT, created_at INTEGER NOT NULL, finished_at INTEGER)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS broadcast_recipients (broadcast_id TEXT NOT NULL, user_id TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', PRIMARY KEY (broadcast_id, user_id))"),
    env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_recipients_status ON broadcast_recipients (broadcast_id, status)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS setup_codes (code TEXT PRIMARY KEY, payload TEXT NOT NULL, iv TEXT NOT NULL, provider TEXT, note TEXT, max_uses INTEGER NOT NULL DEFAULT 1, uses INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL)")
  ]);
  // однократный перенос уже существующих пользователей (у кого сохранены ключи)
  try {
    await env.DB.prepare(
      "INSERT OR IGNORE INTO users (telegram_user_id) SELECT DISTINCT telegram_user_id FROM user_keys"
    ).run();
  } catch {}
  schemaReady = true;
}

/* Регистрация / обновление пользователя при каждом запуске Mini App */
async function touchUser(env, user) {
  await ensureSchema(env);
  await env.DB.prepare(`
    INSERT INTO users (telegram_user_id, first_name, username, language_code, blocked, created_at, last_seen)
    VALUES (?, ?, ?, ?, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    ON CONFLICT(telegram_user_id) DO UPDATE SET
      first_name = excluded.first_name,
      username = excluded.username,
      language_code = excluded.language_code,
      blocked = 0,
      last_seen = CURRENT_TIMESTAMP
  `).bind(
    String(user.id),
    user.first_name || null,
    user.username || null,
    user.language_code || null
  ).run();
}

/* ---------- базовый системный промпт (хранится в D1, правит только администратор) ---------- */
const SYSTEM_PROMPT_KEY = "system_prompt";
const SYSTEM_PROMPT_MAX = 4000;

async function handleConfig(request, env, url) {
  try {
    const a = await authUser(request, env);
    if (a.error) return a.error;

    await ensureSchema(env);

    // GET /config — для всех пользователей приложения (заодно регистрируем пользователя)
    if (url.pathname === "/config") {
      if (request.method !== "GET") return response({ error: "Method not allowed" }, 405);
      try { await touchUser(env, a.user); } catch {}
      const row = await env.DB.prepare(
        "SELECT value FROM app_config WHERE key = ?"
      ).bind(SYSTEM_PROMPT_KEY).first();
      return response({ system_prompt: row ? row.value : null, admin: a.isAdmin });
    }

    // /admin/system-prompt — только администратор
    if (!a.isAdmin) return response({ error: "Forbidden" }, 403);

    if (request.method === "PUT") {
      const body = await request.json();
      if (typeof body.text !== "string") {
        return response({ error: "Field text is required" }, 400);
      }
      const text = body.text.trim();
      if (text.length > SYSTEM_PROMPT_MAX) {
        return response({ error: "Prompt is too long (max " + SYSTEM_PROMPT_MAX + " characters)" }, 400);
      }

      await env.DB.prepare(`
        INSERT INTO app_config (key, value, updated_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(key)
        DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
      `).bind(SYSTEM_PROMPT_KEY, text).run();

      return response({ ok: true });
    }

    if (request.method === "DELETE") {
      await env.DB.prepare("DELETE FROM app_config WHERE key = ?").bind(SYSTEM_PROMPT_KEY).run();
      return response({ ok: true });
    }

    return response({ error: "Method not allowed" }, 405);

  } catch {
    return response({ error: "Server error" }, 500);
  }
}

/* =====================================================================
   РАССЫЛКИ
   ===================================================================== */
const MAX_MEDIA = 10;
const PHOTO_MAX = 10 * 1024 * 1024;
const VIDEO_MAX = 45 * 1024 * 1024;
const CAPTION_MAX = 1024;
const TEXT_MAX = 4000;
const CHUNK = 10;            // сколько пользователей обрабатываем параллельно
const MSG_PER_SEC = 25;      // запас от лимита Telegram (~30 сообщений/с)
const BATCH_DEFAULT = 20;    // пользователей за один вызов /run (укладывается в 50 подзапросов бесплатного плана)

const escHtml = s => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

/* Мини-разметка: **жирный**, *курсив*, `код`, [ссылка](https://…) → HTML Telegram.
   Клиент использует ту же логику для предпросмотра. */
function toHtml(src) {
  const codes = [];
  let s = String(src || "").replace(/`([^`\n]+)`/g, (m, c) => {
    codes.push(c);
    return "\u0000" + (codes.length - 1) + "\u0000";
  });
  s = escHtml(s)
    .replace(/\*\*([^*\n]+)\*\*/g, "<b>$1</b>")
    .replace(/(^|[^*\w])\*([^*\n]+)\*(?!\*)/g, "$1<i>$2</i>")
    .replace(/\[([^\]\n]+)\]\((https?:\/\/[^)\s]+)\)/g, (m, t, u) =>
      '<a href="' + u.replace(/"/g, "&quot;") + '">' + t + "</a>");
  return s.replace(/\u0000(\d+)\u0000/g, (m, i) => "<code>" + escHtml(codes[+i]) + "</code>");
}

function composeHtml(title, text) {
  return ((title ? "<b>" + escHtml(title) + "</b>\n\n" : "") + toHtml(text)).trim();
}

function parseContent(body) {
  const title = typeof body.title === "string" ? body.title.trim().slice(0, 200) : "";
  const text = typeof body.text === "string" ? body.text.trim() : "";
  let media = Array.isArray(body.media) ? body.media : [];
  if (media.length > MAX_MEDIA) return { error: "Не больше " + MAX_MEDIA + " вложений" };
  media = media.map(m => ({
    id: String((m && m.id) || ""),
    type: m && m.type === "video" ? "video" : "photo"
  }));
  if (media.some(m => !/^[\w-]{10,250}$/.test(m.id))) return { error: "Некорректное вложение" };
  if (!title && !text && !media.length) return { error: "Сообщение пустое" };
  const html = composeHtml(title, text);
  if (html.length > TEXT_MAX) return { error: "Текст слишком длинный (максимум около " + TEXT_MAX + " символов)" };
  return { title, text, media, html };
}

async function tgCall(env, method, body) {
  let res;
  try {
    res = await fetch("https://api.telegram.org/bot" + env.TELEGRAM_BOT_TOKEN + "/" + method,
      body instanceof FormData
        ? { method: "POST", body }
        : { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  } catch {
    return { ok: false, error_code: 0, description: "network error" };
  }
  try {
    return await res.json();
  } catch {
    return { ok: false, error_code: res.status, description: "bad response" };
  }
}

const R = r => ({
  ok: !!r.ok,
  code: r.error_code || 0,
  desc: r.description || "",
  retry: (r.parameters && r.parameters.retry_after) || 0
});

/* Отправка одного уведомления в один чат: текст, одно медиа или альбом */
async function sendToChat(env, chatId, html, media) {
  if (!media.length) {
    return R(await tgCall(env, "sendMessage", { chat_id: chatId, text: html, parse_mode: "HTML" }));
  }
  const withCaption = !!html && html.length <= CAPTION_MAX;
  const cap = withCaption ? { caption: html, parse_mode: "HTML" } : {};
  let r;
  if (media.length === 1) {
    const m = media[0];
    r = await tgCall(env, m.type === "video" ? "sendVideo" : "sendPhoto",
      Object.assign({ chat_id: chatId, [m.type === "video" ? "video" : "photo"]: m.id }, cap));
  } else {
    r = await tgCall(env, "sendMediaGroup", {
      chat_id: chatId,
      media: media.map((m, i) => Object.assign({ type: m.type, media: m.id }, i === 0 ? cap : {}))
    });
  }
  let out = R(r);
  if (out.ok && html && !withCaption) {
    out = R(await tgCall(env, "sendMessage", { chat_id: chatId, text: html, parse_mode: "HTML" }));
  }
  return out;
}

function pub(b) {
  let mc = 0;
  try { mc = JSON.parse(b.media || "[]").length; } catch {}
  return {
    id: b.id,
    title: b.title,
    preview: String(b.text || "").slice(0, 120),
    media: mc,
    status: b.status,
    total: b.total,
    sent: b.sent,
    failed: b.failed,
    blocked: b.blocked,
    last_error: b.last_error,
    created_at: b.created_at,
    finished_at: b.finished_at
  };
}

async function getBroadcast(env, id) {
  const b = await env.DB.prepare(
    "SELECT id, title, text, media, status, total, sent, failed, blocked, last_error, created_at, finished_at FROM broadcasts WHERE id = ?"
  ).bind(id).first();
  return b ? pub(b) : null;
}

/* Один шаг рассылки. Блокировка (lock_until) не даёт двум вызовам обрабатывать одну рассылку одновременно. */
async function runBatch(env, id) {
  const limit = Math.max(5, Math.min(500, parseInt(env.BATCH_SIZE) || BATCH_DEFAULT));
  const now = Date.now();

  const claim = await env.DB.prepare(
    "UPDATE broadcasts SET lock_until = ? WHERE id = ? AND status = 'sending' AND lock_until < ?"
  ).bind(now + 60000, id, now).run();

  if (!claim.meta || !claim.meta.changes) {
    const st = await getBroadcast(env, id);
    if (!st) return null;
    if (st.status === "sending") {
      const row = await env.DB.prepare("SELECT lock_until FROM broadcasts WHERE id = ?").bind(id).first();
      const wait = row ? Math.max(0, Math.ceil((row.lock_until - Date.now()) / 1000)) : 0;
      return Object.assign(st, { busy: true, retry_after: Math.min(wait, 60) });
    }
    return st;
  }

  const b = await env.DB.prepare("SELECT * FROM broadcasts WHERE id = ?").bind(id).first();
  const { results: rows } = await env.DB.prepare(
    "SELECT user_id FROM broadcast_recipients WHERE broadcast_id = ? AND status = 'pending' LIMIT ?"
  ).bind(id, limit).all();

  const html = composeHtml(b.title, b.text);
  const media = JSON.parse(b.media || "[]");
  const perUser = (media.length > 1 ? media.length : 1) +
    (media.length && html && html.length > CAPTION_MAX ? 1 : 0);

  let sent = 0, failed = 0, blocked = 0, retryAfter = 0, lastError = null;
  const stmts = [];
  const mark = (uid, status) => stmts.push(
    env.DB.prepare("UPDATE broadcast_recipients SET status = ? WHERE broadcast_id = ? AND user_id = ?").bind(status, id, uid)
  );

  for (let i = 0; i < rows.length && !retryAfter; i += CHUNK) {
    const t0 = Date.now();
    const chunk = rows.slice(i, i + CHUNK);
    const res = await Promise.all(chunk.map(r => sendToChat(env, r.user_id, html, media)));

    res.forEach((r, k) => {
      const uid = chunk[k].user_id;
      if (r.ok) {
        sent++; mark(uid, "sent");
      } else if (r.code === 429) {
        retryAfter = Math.max(retryAfter, r.retry || 5);      // останется pending — повторим позже
      } else if (r.code === 403 || (r.code === 400 && /chat not found|user is deactivated|PEER_ID_INVALID/i.test(r.desc))) {
        blocked++; mark(uid, "blocked");
        stmts.push(env.DB.prepare("UPDATE users SET blocked = 1 WHERE telegram_user_id = ?").bind(uid));
      } else {
        failed++; mark(uid, "failed"); lastError = r.desc || "unknown error";
      }
    });

    const wait = chunk.length * perUser / MSG_PER_SEC * 1000 - (Date.now() - t0);
    if (wait > 0 && i + CHUNK < rows.length && !retryAfter) await sleep(wait);
  }

  stmts.push(env.DB.prepare(
    "UPDATE broadcasts SET sent = sent + ?, failed = failed + ?, blocked = blocked + ?, last_error = COALESCE(?, last_error), lock_until = ? WHERE id = ?"
  ).bind(sent, failed, blocked, lastError, retryAfter ? Date.now() + retryAfter * 1000 : 0, id));
  await env.DB.batch(stmts);

  const left = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM broadcast_recipients WHERE broadcast_id = ? AND status = 'pending'"
  ).bind(id).first();

  if (!left || left.n === 0) {
    await env.DB.batch([
      env.DB.prepare("UPDATE broadcasts SET status = 'done', finished_at = ?, lock_until = 0 WHERE id = ? AND status = 'sending'").bind(Date.now(), id),
      env.DB.prepare("DELETE FROM broadcast_recipients WHERE broadcast_id = ?").bind(id)
    ]);
  }

  const st = await getBroadcast(env, id);
  if (retryAfter) st.retry_after = retryAfter;
  return st;
}

async function createBroadcast(env, body) {
  const token = typeof body.token === "string" ? body.token : "";
  if (!/^[\w-]{8,64}$/.test(token)) return response({ error: "Некорректный токен запуска" }, 400);

  const c = parseContent(body);
  if (c.error) return response({ error: c.error }, 400);

  // защита от повторного запуска: тот же токен возвращает уже созданную рассылку
  const existing = await env.DB.prepare("SELECT id FROM broadcasts WHERE client_token = ?").bind(token).first();
  if (existing) return response(Object.assign(await getBroadcast(env, existing.id), { duplicate: true }));

  // одновременно может идти только одна рассылка
  const active = await env.DB.prepare("SELECT id FROM broadcasts WHERE status = 'sending' LIMIT 1").first();
  if (active) return response({ error: "Другая рассылка ещё не завершена. Продолжите или отмените её в истории.", id: active.id }, 409);

  const cnt = await env.DB.prepare("SELECT COUNT(*) AS n FROM users WHERE blocked = 0").first();
  if (!cnt || !cnt.n) return response({ error: "Нет получателей" }, 400);

  const id = crypto.randomUUID();
  try {
    await env.DB.batch([
      env.DB.prepare("INSERT INTO broadcasts (id, client_token, title, text, media, status, total, created_at) VALUES (?, ?, ?, ?, ?, 'sending', 0, ?)")
        .bind(id, token, c.title, c.text, JSON.stringify(c.media), Date.now()),
      env.DB.prepare("INSERT INTO broadcast_recipients (broadcast_id, user_id) SELECT ?, telegram_user_id FROM users WHERE blocked = 0").bind(id),
      env.DB.prepare("UPDATE broadcasts SET total = (SELECT COUNT(*) FROM broadcast_recipients WHERE broadcast_id = ?) WHERE id = ?").bind(id, id)
    ]);
  } catch {
    // гонка двух одинаковых запросов: сработало ограничение UNIQUE по токену
    const again = await env.DB.prepare("SELECT id FROM broadcasts WHERE client_token = ?").bind(token).first();
    if (again) return response(Object.assign(await getBroadcast(env, again.id), { duplicate: true }));
    throw new Error("create failed");
  }
  return response(await getBroadcast(env, id));
}

async function uploadMedia(request, env, adminId) {
  const form = await request.formData();
  const file = form.get("file");
  if (!file || typeof file !== "object" || !file.size) return response({ error: "Файл не получен" }, 400);

  const isVideo = /^video\//.test(file.type);
  const isPhoto = /^image\/(jpeg|png)$/.test(file.type);
  if (!isVideo && !isPhoto) return response({ error: "Поддерживаются JPEG, PNG и MP4" }, 400);
  if (file.size > (isVideo ? VIDEO_MAX : PHOTO_MAX)) {
    return response({ error: isVideo ? "Видео больше 45 МБ" : "Фото больше 10 МБ" }, 400);
  }

  // Загружаем файл в чат администратора, чтобы получить file_id, и сразу удаляем сообщение.
  // Дальше рассылка использует только file_id — файл не передаётся повторно.
  const fd = new FormData();
  fd.append("chat_id", adminId);
  fd.append("disable_notification", "true");
  fd.append(isVideo ? "video" : "photo", file, file.name || (isVideo ? "video.mp4" : "photo.jpg"));
  if (isVideo) fd.append("supports_streaming", "true");

  const r = await tgCall(env, isVideo ? "sendVideo" : "sendPhoto", fd);
  if (!r.ok) return response({ error: "Telegram: " + (r.description || "ошибка загрузки") }, 400);

  const msg = r.result;
  const fileId = isVideo ? msg.video.file_id : msg.photo[msg.photo.length - 1].file_id;
  await tgCall(env, "deleteMessage", { chat_id: adminId, message_id: msg.message_id });
  return response({ id: fileId, type: isVideo ? "video" : "photo" });
}

async function handleAdmin(request, env, url) {
  try {
    const a = await authUser(request, env);
    if (a.error) return a.error;
    if (!a.isAdmin) return response({ error: "Forbidden" }, 403);
    await ensureSchema(env);

    const p = url.pathname, m = request.method;

    if (p === "/admin/media" && m === "POST") return await uploadMedia(request, env, a.userId);

    if (p === "/admin/broadcasts/test" && m === "POST") {
      const c = parseContent(await request.json());
      if (c.error) return response({ error: c.error }, 400);
      const r = await sendToChat(env, a.userId, c.html, c.media);
      if (!r.ok) return response({ error: "Telegram: " + (r.desc || "не удалось отправить") }, 400);
      return response({ ok: true });
    }

    if (p === "/admin/broadcasts" && m === "GET") {
      const { results } = await env.DB.prepare(
        "SELECT id, title, text, media, status, total, sent, failed, blocked, last_error, created_at, finished_at FROM broadcasts ORDER BY created_at DESC LIMIT 30"
      ).all();
      const u = await env.DB.prepare(
        "SELECT COUNT(*) AS total, COALESCE(SUM(blocked), 0) AS blocked FROM users"
      ).first();
      return response({ items: results.map(pub), users: { total: u.total, blocked: u.blocked } });
    }

    if (p === "/admin/broadcasts" && m === "POST") {
      return await createBroadcast(env, await request.json());
    }

    const mm = p.match(/^\/admin\/broadcasts\/([\w-]{8,64})\/(run|cancel)$/);
    if (mm && m === "POST") {
      const id = mm[1];
      if (mm[2] === "run") {
        const st = await runBatch(env, id);
        return st ? response(st) : response({ error: "Рассылка не найдена" }, 404);
      }
      await env.DB.batch([
        env.DB.prepare("UPDATE broadcasts SET status = 'cancelled', finished_at = ?, lock_until = 0 WHERE id = ? AND status = 'sending'").bind(Date.now(), id),
        env.DB.prepare("DELETE FROM broadcast_recipients WHERE broadcast_id = ?").bind(id)
      ]);
      const st = await getBroadcast(env, id);
      return st ? response(st) : response({ error: "Рассылка не найдена" }, 404);
    }

    return response({ error: "Not found" }, 404);
  } catch (e) {
    return response({ error: "Server error: " + ((e && e.message) || "unknown") }, 500);
  }
}

/* Необязательный webhook бота: /start регистрирует пользователя, my_chat_member отслеживает блокировки.
   Включается, только если задан секрет WEBHOOK_SECRET. */
async function handleWebhook(request, env) {
  if (!env.WEBHOOK_SECRET || request.method !== "POST") return new Response("Not found", { status: 404 });
  if (request.headers.get("X-Telegram-Bot-Api-Secret-Token") !== env.WEBHOOK_SECRET) {
    return new Response("Forbidden", { status: 403 });
  }
  try {
    const upd = await request.json();
    await ensureSchema(env);

    const msg = upd.message;
    if (msg && msg.chat && msg.chat.type === "private" && msg.from && !msg.from.is_bot) {
      await touchUser(env, msg.from);
    }

    const mc = upd.my_chat_member;
    if (mc && mc.chat && mc.chat.type === "private" && mc.new_chat_member) {
      const st = mc.new_chat_member.status;
      if (st === "kicked") {
        await env.DB.prepare("UPDATE users SET blocked = 1 WHERE telegram_user_id = ?").bind(String(mc.chat.id)).run();
      } else if (st === "member") {
        await touchUser(env, mc.from);
      }
    }
  } catch {}
  return new Response("ok");
}

/* =====================================================================
   БЫСТРАЯ НАСТРОЙКА (коды)
   ===================================================================== */
const CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
function genCode() {
  const b = crypto.getRandomValues(new Uint8Array(10));
  let s = "";
  for (const x of b) s += CODE_ALPHABET[x % 32];
  return s.slice(0, 5) + "-" + s.slice(5);
}
function normCode(v) {
  const s = String(v || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
  return s.length === 10 ? s.slice(0, 5) + "-" + s.slice(5) : "";
}

async function handleSetup(request, env, url) {
  try {
    const a = await authUser(request, env);
    if (a.error) return a.error;
    await ensureSchema(env);
    const p = url.pathname, m = request.method;

    // погашение кода — любой пользователь приложения
    if (p === "/setup/redeem" && m === "POST") {
      const code = normCode((await request.json()).code);
      if (!code) return response({ error: "Неверный код" }, 400);
      const r = await env.DB.prepare(
        "UPDATE setup_codes SET uses = uses + 1 WHERE code = ? AND revoked = 0 AND uses < max_uses AND expires_at > ?"
      ).bind(code, Date.now()).run();
      if (!r.meta || !r.meta.changes) return response({ error: "Код недействителен, уже использован или истёк" }, 400);
      const row = await env.DB.prepare("SELECT payload, iv FROM setup_codes WHERE code = ?").bind(code).first();
      return response(JSON.parse(await decryptKey(row.payload, row.iv, env.ENCRYPTION_SECRET)));
    }

    if (!a.isAdmin) return response({ error: "Forbidden" }, 403);

    if (p === "/admin/setup-codes" && m === "POST") {
      const b = await request.json();
      if (!validProvider(b.provider)) return response({ error: "Неверный провайдер" }, 400);
      const key = typeof b.key === "string" ? b.key.trim() : "";
      if (key.length > 10000) return response({ error: "Ключ слишком длинный" }, 400);
      const payload = {
        provider: b.provider,
        key,
        base: typeof b.base === "string" ? b.base.trim().slice(0, 300) : "",
        name: typeof b.name === "string" ? b.name.trim().slice(0, 40) : "",
        limit: Math.max(0, parseInt(b.limit) || 0),
        models: (Array.isArray(b.models) ? b.models : []).filter(x => typeof x === "string" && x.length < 120).slice(0, 100)
      };
      const maxUses = Math.min(100, Math.max(1, parseInt(b.max_uses) || 1));
      const days = Math.min(90, Math.max(1, parseInt(b.days) || 7));
      const enc = await encryptKey(JSON.stringify(payload), env.ENCRYPTION_SECRET);
      const code = genCode(), now = Date.now();
      await env.DB.prepare(
        "INSERT INTO setup_codes (code, payload, iv, provider, note, max_uses, created_at, expires_at) VALUES (?,?,?,?,?,?,?,?)"
      ).bind(code, enc.encrypted_key, enc.iv, b.provider, String(b.note || "").slice(0, 60), maxUses, now, now + days * 864e5).run();
      return response({ code });
    }

    if (p === "/admin/setup-codes" && m === "GET") {
      const { results } = await env.DB.prepare(
        "SELECT code, provider, note, max_uses, uses, revoked, expires_at FROM setup_codes ORDER BY created_at DESC LIMIT 30"
      ).all();
      return response({ items: results });
    }

    const mm = p.match(/^\/admin\/setup-codes\/([A-Z0-9-]{11})$/);
    if (mm && m === "DELETE") {
      if (url.searchParams.get("purge") === "1") {
        await env.DB.prepare("DELETE FROM setup_codes WHERE code = ?").bind(mm[1]).run();
      } else {
        await env.DB.prepare("UPDATE setup_codes SET revoked = 1 WHERE code = ?").bind(mm[1]).run();
      }
      return response({ ok: true });
    }
    return response({ error: "Not found" }, 404);
  } catch (e) {
    return response({ error: "Server error" }, 500);
  }
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin");

    if (origin && origin !== ALLOWED_ORIGIN) {
      return new Response("Forbidden", { status: 403 });
    }

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
          "Access-Control-Allow-Methods": CORS_METHODS,
          "Access-Control-Allow-Headers": "Content-Type, X-Telegram-Init-Data",
          "Access-Control-Max-Age": "86400",
          "Vary": "Origin"
        }
      });
    }

    const url = new URL(request.url);

    if (url.pathname === "/health" && request.method === "GET") {
      try {
        await env.DB.prepare("SELECT 1").first();
        return response({ ok: true, database: true });
      } catch {
        return response({ ok: false, error: "Database unavailable" }, 500);
      }
    }

    if (url.pathname === "/webhook") return handleWebhook(request, env);

    if (url.pathname === "/config" || url.pathname === "/admin/system-prompt") {
      return handleConfig(request, env, url);
    }

    if (url.pathname === "/admin/media" || url.pathname.startsWith("/admin/broadcasts")) {
      return handleAdmin(request, env, url);
    }

    if (url.pathname === "/setup/redeem" || url.pathname.startsWith("/admin/setup-codes")) {
      return handleSetup(request, env, url);
    }

    if (url.pathname !== "/keys") {
      return response({ error: "Not found" }, 404);
    }

    try {
      const a = await authUser(request, env);
      if (a.error) return a.error;
      const userId = a.userId;

      const provider = url.searchParams.get("provider");

      if (request.method === "GET") {
        if (!validProvider(provider)) {
          return response({ error: "Invalid provider" }, 400);
        }

        const row = await env.DB.prepare(
          "SELECT encrypted_key, iv FROM user_keys WHERE telegram_user_id = ? AND provider = ?"
        ).bind(userId, provider).first();

        if (!row) return response({ key: null });

        const key = await decryptKey(
          row.encrypted_key,
          row.iv,
          env.ENCRYPTION_SECRET
        );

        return response({ key });
      }

      if (request.method === "PUT") {
        const body = await request.json();
        const selectedProvider = body.provider;
        const apiKey = body.key;

        if (!validProvider(selectedProvider)) {
          return response({ error: "Invalid provider" }, 400);
        }

        if (typeof apiKey !== "string" || apiKey.length < 1 || apiKey.length > 10000) {
          return response({ error: "Invalid API key" }, 400);
        }

        const encrypted = await encryptKey(apiKey, env.ENCRYPTION_SECRET);

        await env.DB.prepare(`
          INSERT INTO user_keys (telegram_user_id, provider, encrypted_key, iv, updated_at)
          VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
          ON CONFLICT(telegram_user_id, provider)
          DO UPDATE SET encrypted_key = excluded.encrypted_key,
                        iv = excluded.iv,
                        updated_at = CURRENT_TIMESTAMP
        `).bind(
          userId,
          selectedProvider,
          encrypted.encrypted_key,
          encrypted.iv
        ).run();

        return response({ ok: true });
      }

      if (request.method === "DELETE") {
        if (!validProvider(provider)) {
          return response({ error: "Invalid provider" }, 400);
        }

        await env.DB.prepare(
          "DELETE FROM user_keys WHERE telegram_user_id = ? AND provider = ?"
        ).bind(userId, provider).run();

        return response({ ok: true });
      }

      return response({ error: "Method not allowed" }, 405);

    } catch {
      return response({ error: "Server error" }, 500);
    }
  },

  /* Необязательный Cron Trigger (раз в минуту): дорассылает незавершённые рассылки, даже если приложение закрыто */
  async scheduled(event, env, ctx) {
    ctx.waitUntil((async () => {
      await ensureSchema(env);
      const { results } = await env.DB.prepare("SELECT id FROM broadcasts WHERE status = 'sending'").all();
      for (const r of results) await runBatch(env, r.id);
    })());
  }
};
