import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

/*
  Monthly Target Tracker API  (all routes under /api/)
  ------------------------------------------------------------------
  Public
    GET  /api/data                 current month dashboard data
    GET  /api/photo?id=            staff photo
  Any signed-in role (admin / manager / staff)
    GET  /api/whoami               -> {role, name, staffId}
    GET  /api/profile?id=          monthly history + behaviour log (staff: own id only)
    POST /api/pin/change           staff changes own PIN        {newPin}
    POST /api/log/ack              staff acknowledges an entry   {eid, text}
  Manager or admin
    GET  /api/profiles             all staff monthly history + all logs (warnings / overview)
    POST /api/log                  add behaviour entry           {id, type, severity, date, text, visible}
    POST /api/log/show             make a private entry visible  {id, eid}
    GET  /api/months               month index (?ym= for one month incl. rows)
  Admin only
    POST /api/data, /api/photo, DELETE /api/photo
    POST /api/months               {months:[{ym, rows, tg, staff, summary, source}]}
    DELETE /api/months?ym=
  Manager or admin (roster)
    GET  /api/roster/sheet?id=     proxy: Google Sheet export (xlsx) — sheet must be "anyone with the link can view"
    POST /api/roster               {months:{ym:{id:{day:[status,code]}}}, meta}  (replaces given months)
    GET/POST /api/pin              status / set or clear a staff PIN {id, pin|null}
    GET/POST/DELETE /api/managers  manager keys {name, key} / ?mid=
    POST /api/log/void             void an entry                 {id, eid, reason}
*/

const HDR = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" };
const json = (b, s = 200) => new Response(typeof b === "string" ? b : JSON.stringify(b), { status: s, headers: HDR });
const hashSecret = (v, salt) => crypto.pbkdf2Sync(String(v), salt, 60000, 32, "sha256").toString("hex");
const newSalt = () => crypto.randomBytes(16).toString("hex");
const safeEq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const cleanId = (v) => String(v ?? "").replace(/[^0-9A-Za-z_-]/g, "");
const YM = /^\d{4}-\d{2}$/;
const MAX_PHOTO = 1_500_000;
const LOG_TYPES = ["praise", "attendance", "verbal", "written", "complaint", "meeting", "other"];
const SHIFT_ST = ["off", "leave", "absent", "work"];  // "work" = manual override of a roster off/leave day
const median = (arr) => { const s = arr.filter((v) => Number.isFinite(v)).sort((a, b) => a - b); if (!s.length) return 0; const h = s.length >> 1; return s.length % 2 ? s[h] : (s[h - 1] + s[h]) / 2; };
/* Recompute the "consistency" stat from the shift calendar.
   Work days = days 1..last, minus days marked off/leave (sales on those days still count in totals, not in consistency).
   Absent days count as work days that missed the target. No marks for a person-month = fall back to days with sales. */
/* effective marks for one person-month: roster (Google Sheet) first, manual marks override */
function effMarks(manual, roster) {
  const out = {};
  for (const [d, v] of Object.entries(roster || {})) { const st = Array.isArray(v) ? v[0] : v; if (st === "off" || st === "leave") out[d] = st; }
  for (const [d, st] of Object.entries(manual || {})) { if (st === "work") delete out[d]; else if (SHIFT_ST.includes(st)) out[d] = st; }
  return out;
}
function applyShifts(sum, shifts, roster) {
  const sm = (shifts || {})[sum.ym] || {};
  const rm = ((roster && roster.months) || {})[sum.ym] || {};
  const L = [];
  for (const o of Object.values(sum.staff || {})) {
    const marks = effMarks(sm[String(o.id)], rm[String(o.id)]);
    const cnt = { off: 0, leave: 0, absent: 0 };
    for (const [d, st] of Object.entries(marks)) if (+d <= sum.last && cnt[st] != null) cnt[st]++;
    o.marks = cnt;
    if (o.daily && Object.keys(marks).length) {
      let work = 0, hit = 0;
      for (let d = 1; d <= sum.last; d++) {
        const st = marks[String(d)], s = o.daily[String(d)] || 0;
        if (st === "off" || st === "leave") continue;
        work++; if (o.dT > 0 && s >= o.dT) hit++;
      }
      o.daysHit = hit; o.daysSales = work; o.cons = work ? hit / work : 0; o.consMode = "cal";
    } else o.consMode = "sales";
    if (o.tgSales > 0) L.push(o);
  }
  if (sum.team && sum.team.med) sum.team.med.cons = median(L.map((o) => o.cons));
  return sum;
}

export default async (req) => {
  const store = getStore({ name: "w7-dashboard", consistency: "strong" });
  const url = new URL(req.url);
  const route = url.pathname.replace(/^\/api\/?/, "").replace(/\/+$/, "");
  const method = req.method;

  const ADMIN = process.env.ADMIN_KEY || "";
  const adminGiven = req.headers.get("x-admin-key") || "";
  const isAdmin = ADMIN.length > 0 && adminGiven.length > 0 && safeEq(adminGiven, ADMIN);

  const getJ = async (key, def) => { const v = await store.get(key, { type: "json" }); return v ?? def; };
  let auth = null;
  const loadAuth = async () => (auth ??= await getJ("auth", { managers: [], pins: {}, locks: {} }));
  const saveAuth = () => store.setJSON("auth", auth);
  const body = async () => { try { return await req.json(); } catch { return null; } };

  // ---------- identify caller ----------
  async function who() {
    if (isAdmin) return { role: "admin", name: "ผู้ดูแล" };
    const mk = req.headers.get("x-manager-key");
    if (mk) {
      await loadAuth();
      for (const m of auth.managers) if (safeEq(hashSecret(mk, m.salt), m.hash)) return { role: "manager", name: m.name, mid: m.mid };
      return { bad: true };
    }
    const sid = cleanId(req.headers.get("x-staff-id")), pin = req.headers.get("x-staff-pin");
    if (sid && pin) {
      await loadAuth();
      const lk = auth.locks[sid] || { fails: 0, until: 0 };
      if (lk.until > Date.now()) return { locked: true, until: lk.until };
      const rec = auth.pins[sid];
      if (rec && safeEq(hashSecret(pin, rec.salt), rec.hash)) {
        if (auth.locks[sid]) { delete auth.locks[sid]; await saveAuth(); }
        return { role: "staff", staffId: sid, name: rec.name || "" };
      }
      lk.fails = (lk.fails || 0) + 1;
      if (lk.fails >= 5) { lk.until = Date.now() + 15 * 60 * 1000; lk.fails = 0; }
      auth.locks[sid] = lk; await saveAuth();
      return { bad: true, noPin: !rec, left: lk.until ? 0 : 5 - lk.fails, until: lk.until || 0 };
    }
    return null;
  }
  const deny = (w) => w && w.locked ? json({ error: "locked", until: w.until }, 423)
    : json({ error: "unauthorized", noPin: w && w.noPin, left: w && w.left, until: w && w.until }, 401);

  /* ---------------- photos ---------------- */
  if (route === "photo") {
    const id = cleanId(url.searchParams.get("id"));
    if (!id) return json({ error: "missing id" }, 400);
    const key = `photo-${id}`;
    if (method === "GET") {
      const res = await store.getWithMetadata(key, { type: "arrayBuffer" });
      if (!res || !res.data) return new Response("not found", { status: 404 });
      return new Response(res.data, { headers: { "content-type": (res.metadata && res.metadata.type) || "image/jpeg", "cache-control": "public, max-age=31536000, immutable" } });
    }
    if (!isAdmin) return json({ error: "unauthorized" }, 401);
    if (method === "POST") {
      const type = req.headers.get("content-type") || "image/jpeg";
      if (!type.startsWith("image/")) return json({ error: "not an image" }, 400);
      const buf = await req.arrayBuffer();
      if (!buf.byteLength) return json({ error: "empty" }, 400);
      if (buf.byteLength > MAX_PHOTO) return json({ error: "too large" }, 413);
      await store.set(key, buf, { metadata: { type } });
      return json({ ok: true });
    }
    if (method === "DELETE") { await store.delete(key); return json({ ok: true }); }
    return json({ error: "method not allowed" }, 405);
  }

  /* ---------------- current dashboard data ---------------- */
  if (route === "data") {
    if (method === "GET") {
      if (url.searchParams.has("auth")) return new Response(null, { status: isAdmin ? 204 : 401 });
      // light poll: only the save stamp, so open pages re-download the full data only when it changed
      if (url.searchParams.has("stamp")) return json({ s: (await store.get("stamp", { type: "text" })) || null });
      return json((await store.get("state", { type: "text" })) || "null");
    }
    if (method === "POST") {
      if (!isAdmin) return json({ error: "unauthorized" }, 401);
      const text = await req.text();
      if (text.length > 4_000_000) return json({ error: "too large" }, 413);
      let p; try { p = JSON.parse(text); } catch { return json({ error: "bad json" }, 400); }
      if (!p || !Array.isArray(p.rows)) return json({ error: "missing rows" }, 400);
      await store.set("state", text);
      await store.set("stamp", String(p.savedAt || Date.now()));
      return json({ ok: true });
    }
    return json({ error: "method not allowed" }, 405);
  }

  /* ---------------- past months for the dashboard (public, like the current month) ---------------- */
  if (route === "history" && method === "GET") {
    const ym = url.searchParams.get("ym");
    if (!ym) return json((await getJ("months-index", [])).map((e) => ({ ym: e.ym, last: e.last, dim: e.dim })));
    if (!YM.test(ym)) return json({ error: "bad ym" }, 400);
    const m = await getJ(`mrows-${ym}`, null);
    if (!m) return json({ error: "not found" }, 404);
    return json({ ym: m.ym, rows: m.rows, tg: m.tg || {}, staff: m.staff || [], x: m.x || null });
  }

  /* ---------------- everything below needs a signed-in caller ---------------- */
  const w = await who();
  if (!w || !w.role) return deny(w);
  const isMgr = w.role === "manager" || w.role === "admin";

  if (route === "whoami") return json({ role: w.role, name: w.name, staffId: w.staffId || null });

  // ----- months -----
  if (route === "months") {
    if (method === "GET") {
      if (!isMgr) return json({ error: "forbidden" }, 403);
      const ym = url.searchParams.get("ym");
      if (ym) { if (!YM.test(ym)) return json({ error: "bad ym" }, 400); return json((await getJ(`mrows-${ym}`, null)) || null); }
      return json(await getJ("months-index", []));
    }
    if (!isAdmin) return json({ error: "forbidden" }, 403);
    if (method === "POST") {
      const b = await body();
      if (!b || !Array.isArray(b.months)) return json({ error: "bad body" }, 400);
      const idx = await getJ("months-index", []);
      for (const m of b.months) {
        if (!m || !YM.test(m.ym) || !Array.isArray(m.rows) || !m.summary) return json({ error: "bad month" }, 400);
        let x = m.x;
        if (x === undefined) { const old = await getJ(`mrows-${m.ym}`, null); x = (old && old.x) || null; }
        if (x && typeof x === "object") { const cx = {}; let n = 0;
          for (const [d, o] of Object.entries(x)) { if (!/^\d{4}-\d{2}-\d{2}$/.test(d) || !o || typeof o !== "object") continue; const co = {};
            for (const [k, v] of Object.entries(o)) { if (++n > 20000) break; const nv = Number(v); if (isFinite(nv)) co[String(k).slice(0, 80)] = Math.round(nv * 100) / 100; }
            cx[d] = co; }
          x = cx; } else x = null;
        await store.setJSON(`mrows-${m.ym}`, { ym: m.ym, rows: m.rows, tg: m.tg || {}, staff: m.staff || [], source: m.source || "", x, updatedAt: Date.now() });
        await store.setJSON(`msum-${m.ym}`, m.summary);
        const e = { ym: m.ym, last: m.summary.last, dim: m.summary.dim, source: m.source || "", updatedAt: Date.now(), n: Object.keys(m.summary.staff || {}).length, sv: m.summary.sv || 1 };
        const i = idx.findIndex((x) => x.ym === m.ym); if (i >= 0) idx[i] = e; else idx.push(e);
      }
      idx.sort((a, b2) => (a.ym < b2.ym ? -1 : 1));
      await store.setJSON("months-index", idx);
      return json({ ok: true, index: idx });
    }
    if (method === "DELETE") {
      const ym = url.searchParams.get("ym"); if (!YM.test(ym || "")) return json({ error: "bad ym" }, 400);
      await store.delete(`mrows-${ym}`); await store.delete(`msum-${ym}`);
      const idx = (await getJ("months-index", [])).filter((x) => x.ym !== ym);
      await store.setJSON("months-index", idx);
      return json({ ok: true, index: idx });
    }
    return json({ error: "method not allowed" }, 405);
  }

  // ----- profile(s) -----
  const loadSummaries = async () => {
    const idx = await getJ("months-index", []);
    const out = [];
    for (const e of idx) { const s = await getJ(`msum-${e.ym}`, null); if (s) out.push(s); }
    return out;
  };
  const visibleLogs = (list, role) => (list || []).filter((e) => role !== "staff" || (e.visible && !e.voided))
    .map((e) => role === "staff" ? { eid: e.eid, date: e.date, type: e.type, severity: e.severity, text: e.text, by: e.by, at: e.at, ack: e.ack || null } : e);

  if (route === "profile" && method === "GET") {
    const id = cleanId(url.searchParams.get("id") || w.staffId);
    if (!id) return json({ error: "missing id" }, 400);
    if (w.role === "staff" && id !== w.staffId) return json({ error: "forbidden" }, 403);
    const shifts = await getJ("shifts", {});
    const roster = await getJ("roster", { months: {} });
    const sums = (await loadSummaries()).map((s) => applyShifts(s, shifts, roster));
    const myShifts = {}; for (const [ym, m] of Object.entries(shifts)) if (m[id]) myShifts[ym] = m[id];
    const myRoster = {}; for (const [ym, m] of Object.entries(roster.months || {})) if (m[id]) myRoster[ym] = m[id];
    const months = sums.filter((s) => s.staff && s.staff[id]).map((s) => ({ ym: s.ym, dim: s.dim, last: s.last, me: s.staff[id], team: s.team }));
    const logs = await getJ("logs", {});
    return json({ id, months, logs: visibleLogs(logs[id], w.role), shifts: myShifts, roster: myRoster });
  }
  if (route === "profiles" && method === "GET") {
    if (!isMgr) return json({ error: "forbidden" }, 403);
    const shifts = await getJ("shifts", {});
    const roster = await getJ("roster", { months: {} });
    return json({ months: (await loadSummaries()).map((s) => applyShifts(s, shifts, roster)), logs: await getJ("logs", {}), shifts, roster: roster.months || {}, rosterMeta: roster.meta || null });
  }

  // ----- behaviour log -----
  if (route.startsWith("log") && method === "POST") {
    const b = (await body()) || {};
    const logs = await getJ("logs", {});
    const id = cleanId(b.id || w.staffId);
    const list = logs[id] || [];
    const find = () => list.find((e) => e.eid === b.eid);
    if (route === "log") {
      if (!isMgr) return json({ error: "forbidden" }, 403);
      const text = String(b.text || "").trim().slice(0, 2000);
      if (!id || !text) return json({ error: "missing id/text" }, 400);
      const e = {
        eid: crypto.randomBytes(6).toString("hex"), id,
        date: /^\d{4}-\d{2}-\d{2}$/.test(b.date || "") ? b.date : new Date().toISOString().slice(0, 10),
        type: LOG_TYPES.includes(b.type) ? b.type : "other",
        severity: ["low", "mid", "high"].includes(b.severity) ? b.severity : "low",
        text, visible: b.visible !== false, by: w.name, byRole: w.role, at: Date.now(),
      };
      list.push(e); logs[id] = list; await store.setJSON("logs", logs);
      return json({ ok: true, entry: e });
    }
    if (route === "log/show") {
      if (!isMgr) return json({ error: "forbidden" }, 403);
      const e = find(); if (!e) return json({ error: "not found" }, 404);
      e.visible = true; e.shownBy = w.name; e.shownAt = Date.now();
      await store.setJSON("logs", logs); return json({ ok: true });
    }
    if (route === "log/void") {
      if (w.role !== "admin") return json({ error: "forbidden" }, 403);
      const e = find(); if (!e) return json({ error: "not found" }, 404);
      e.voided = { by: w.name, at: Date.now(), reason: String(b.reason || "").slice(0, 500) };
      await store.setJSON("logs", logs); return json({ ok: true });
    }
    if (route === "log/ack") {
      if (w.role !== "staff" || id !== w.staffId) return json({ error: "forbidden" }, 403);
      const e = find(); if (!e || !e.visible || e.voided) return json({ error: "not found" }, 404);
      if (e.ack) return json({ error: "already acknowledged" }, 409);
      e.ack = { at: Date.now(), text: String(b.text || "").trim().slice(0, 1000) };
      await store.setJSON("logs", logs); return json({ ok: true, ack: e.ack });
    }
    return json({ error: "not found" }, 404);
  }

  // ----- shift calendar -----
  if (route === "shifts" && method === "POST") {
    if (!isMgr) return json({ error: "forbidden" }, 403);
    const b = (await body()) || {};
    const id = cleanId(b.id), ym = String(b.ym || ""), day = Number(b.day);
    const changes = Array.isArray(b.changes) ? b.changes : [{ id, ym, day, status: b.status }];
    const shifts = await getJ("shifts", {});
    for (const c of changes) {
      const cid = cleanId(c.id), cym = String(c.ym || ""), cd = Number(c.day);
      if (!cid || !YM.test(cym) || !(cd >= 1 && cd <= 31)) return json({ error: "bad change" }, 400);
      const m = (shifts[cym] ||= {}); const p = (m[cid] ||= {});
      if (SHIFT_ST.includes(c.status)) p[String(cd)] = c.status; else delete p[String(cd)];
      if (!Object.keys(p).length) delete m[cid];
      if (!Object.keys(m).length) delete shifts[cym];
    }
    await store.setJSON("shifts", shifts);
    return json({ ok: true });
  }

  // ----- roster (work schedule from Google Sheet) -----
  if (route === "roster/sheet" && method === "GET") {
    if (!isMgr) return json({ error: "forbidden" }, 403);
    const sid = String(url.searchParams.get("id") || "");
    if (!/^[A-Za-z0-9_-]{20,100}$/.test(sid)) return json({ error: "ลิงก์ Google Sheet ไม่ถูกต้อง" }, 400);
    let r;
    try { r = await fetch(`https://docs.google.com/spreadsheets/d/${sid}/export?format=xlsx`, { redirect: "follow" }); }
    catch (e) { return json({ error: "ติดต่อ Google Sheets ไม่ได้" }, 502); }
    const ct = r.headers.get("content-type") || "";
    if (!r.ok || ct.includes("text/html")) return json({ error: "เปิดชีตไม่ได้ — ตั้งแชร์เป็น \"ทุกคนที่มีลิงก์ดูได้\" ก่อน", status: r.status }, 403);
    const buf = await r.arrayBuffer();
    if (buf.byteLength > 5_500_000) return json({ error: "ไฟล์ตารางงานใหญ่เกินไป" }, 413);
    return new Response(buf, { headers: { "content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "cache-control": "no-store" } });
  }
  if (route === "roster" && method === "POST") {
    if (!isMgr) return json({ error: "forbidden" }, 403);
    const b = (await body()) || {};
    if (!b.months || typeof b.months !== "object") return json({ error: "bad body" }, 400);
    const roster = await getJ("roster", { months: {} });
    roster.months ||= {};
    for (const [ym, m] of Object.entries(b.months)) {
      if (!YM.test(ym) || !m || typeof m !== "object") return json({ error: "bad month" }, 400);
      const clean = {};
      for (const [id, days] of Object.entries(m)) {
        const cid = cleanId(id); if (!cid || !days || typeof days !== "object") continue;
        const o = {};
        for (const [d, v] of Object.entries(days)) {
          const dd = Number(d); if (!(dd >= 1 && dd <= 31) || !Array.isArray(v)) continue;
          const st = ["off", "leave", ""].includes(v[0]) ? v[0] : "";
          o[String(dd)] = [st, String(v[1] ?? "").slice(0, 12)];
        }
        clean[cid] = o;
      }
      roster.months[ym] = clean;
    }
    const meta = b.meta && typeof b.meta === "object" ? b.meta : {};
    roster.meta = { at: Date.now(), by: w.name, source: String(meta.source || "").slice(0, 200), tabs: Array.isArray(meta.tabs) ? meta.tabs.slice(0, 24).map((t) => String(t).slice(0, 40)) : [], warn: Array.isArray(meta.warn) ? meta.warn.slice(0, 40).map((t) => String(t).slice(0, 200)) : [],
      order: { ...((roster.meta && roster.meta.order) || {}), ...Object.fromEntries(Object.entries(meta.order && typeof meta.order === "object" ? meta.order : {}).filter(([ym, a]) => YM.test(ym) && Array.isArray(a)).slice(0, 24).map(([ym, a]) => [ym, a.slice(0, 300).map((x) => String(x).replace(/\D/g, "").slice(0, 12))])) } };
    await store.setJSON("roster", roster);
    return json({ ok: true, meta: roster.meta });
  }

  // ----- PIN -----
  if (route === "pin/change" && method === "POST") {
    if (w.role !== "staff") return json({ error: "forbidden" }, 403);
    const b = (await body()) || {}; const np = String(b.newPin || "");
    if (!/^\d{4,8}$/.test(np)) return json({ error: "PIN ต้องเป็นตัวเลข 4–8 หลัก" }, 400);
    await loadAuth(); const salt = newSalt();
    auth.pins[w.staffId] = { ...auth.pins[w.staffId], salt, hash: hashSecret(np, salt), changedAt: Date.now(), bySelf: true };
    await saveAuth(); return json({ ok: true });
  }
  if (route === "pin") {
    if (w.role !== "admin") return json({ error: "forbidden" }, 403);
    await loadAuth();
    if (method === "GET") {
      const st = {}; for (const [id, r] of Object.entries(auth.pins)) st[id] = { set: true, bySelf: !!r.bySelf, at: r.changedAt || 0 };
      const locks = {}; for (const [id, l] of Object.entries(auth.locks)) if (l.until > Date.now()) locks[id] = l.until;
      return json({ pins: st, locks });
    }
    if (method === "POST") {
      const b = (await body()) || {}; const id = cleanId(b.id);
      if (!id) return json({ error: "missing id" }, 400);
      if (b.pin == null || b.pin === "") { delete auth.pins[id]; delete auth.locks[id]; await saveAuth(); return json({ ok: true, cleared: true }); }
      if (!/^\d{4,8}$/.test(String(b.pin))) return json({ error: "PIN ต้องเป็นตัวเลข 4–8 หลัก" }, 400);
      const salt = newSalt();
      auth.pins[id] = { salt, hash: hashSecret(b.pin, salt), changedAt: Date.now(), bySelf: false, name: String(b.name || "") };
      delete auth.locks[id]; await saveAuth(); return json({ ok: true });
    }
    return json({ error: "method not allowed" }, 405);
  }

  // ----- managers -----
  if (route === "managers") {
    if (w.role !== "admin") return json({ error: "forbidden" }, 403);
    await loadAuth();
    if (method === "GET") return json(auth.managers.map((m) => ({ mid: m.mid, name: m.name, at: m.at })));
    if (method === "POST") {
      const b = (await body()) || {}; const name = String(b.name || "").trim().slice(0, 60), key = String(b.key || "");
      if (!name || key.length < 6) return json({ error: "ต้องมีชื่อ และรหัสอย่างน้อย 6 ตัวอักษร" }, 400);
      for (const m of auth.managers) if (safeEq(hashSecret(key, m.salt), m.hash)) return json({ error: "รหัสนี้ถูกใช้แล้ว" }, 409);
      const salt = newSalt();
      auth.managers.push({ mid: crypto.randomBytes(5).toString("hex"), name, salt, hash: hashSecret(key, salt), at: Date.now() });
      await saveAuth(); return json({ ok: true });
    }
    if (method === "DELETE") {
      const mid = url.searchParams.get("mid");
      auth.managers = auth.managers.filter((m) => m.mid !== mid); await saveAuth(); return json({ ok: true });
    }
    return json({ error: "method not allowed" }, 405);
  }

  return json({ error: "not found" }, 404);
};

export const config = { path: "/api/*" };
