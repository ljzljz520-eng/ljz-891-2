'use strict';

const crypto = require('crypto');

const SESSION_TTL = 12 * 3600 * 1000; // 12 小时，滑动过期
const sessions = new Map(); // sid -> { adminId, username, expires }

function createSession(admin) {
  const sid = crypto.randomBytes(24).toString('hex');
  sessions.set(sid, { adminId: admin.id, username: admin.username, expires: Date.now() + SESSION_TTL });
  return sid;
}

function getSession(sid) {
  const s = sessions.get(sid);
  if (!s) return null;
  if (s.expires < Date.now()) {
    sessions.delete(sid);
    return null;
  }
  s.expires = Date.now() + SESSION_TTL; // 滑动续期
  return s;
}

function destroySession(sid) {
  sessions.delete(sid);
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > -1) {
      try {
        out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
      } catch {
        /* 忽略畸形 cookie */
      }
    }
  }
  return out;
}

module.exports = { createSession, getSession, destroySession, parseCookies, SESSION_TTL };
