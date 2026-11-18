import { getStore } from "@netlify/blobs";

// GET    /api/data            -> latest dashboard data (public, for viewers)
// GET    /api/data?auth=1     -> 204 if x-admin-key is correct, else 401
// POST   /api/data            -> save data            (admin only)
// GET    /api/photo?id=123    -> staff photo (public, cached)
// POST   /api/photo?id=123    -> upload staff photo   (admin only, image body)
// DELETE /api/photo?id=123    -> remove staff photo   (admin only)
const json = (body, status = 200) =>
  new Response(typeof body === "string" ? body : JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });

const MAX_PHOTO = 1_500_000;

export default async (req) => {
  const store = getStore({ name: "w7-dashboard", consistency: "strong" });
  const adminKey = process.env.ADMIN_KEY || "";
  const given = req.headers.get("x-admin-key") || "";
  const isAdmin = adminKey.length > 0 && given === adminKey;
  const url = new URL(req.url);

  /* ---------- photos ---------- */
  if (url.pathname.startsWith("/api/photo")) {
    const id = (url.searchParams.get("id") || "").replace(/[^0-9A-Za-z_-]/g, "");
    if (!id) return json({ error: "missing id" }, 400);
    const key = `photo-${id}`;

    if (req.method === "GET") {
      const res = await store.getWithMetadata(key, { type: "arrayBuffer" });
      if (!res || !res.data) return new Response("not found", { status: 404 });
      return new Response(res.data, {
        headers: {
          "content-type": (res.metadata && res.metadata.type) || "image/jpeg",
          // URL carries a version (&v=...), so it is safe to cache for a long time
          "cache-control": "public, max-age=31536000, immutable",
        },
      });
    }
    if (!isAdmin) return json({ error: "unauthorized" }, 401);
    if (req.method === "POST") {
      const type = req.headers.get("content-type") || "image/jpeg";
      if (!type.startsWith("image/")) return json({ error: "not an image" }, 400);
      const buf = await req.arrayBuffer();
      if (buf.byteLength === 0) return json({ error: "empty" }, 400);
      if (buf.byteLength > MAX_PHOTO) return json({ error: "too large" }, 413);
      await store.set(key, buf, { metadata: { type } });
      return json({ ok: true });
    }
    if (req.method === "DELETE") {
      await store.delete(key);
      return json({ ok: true });
    }
    return json({ error: "method not allowed" }, 405);
  }

  /* ---------- dashboard data ---------- */
  if (req.method === "GET") {
    if (url.searchParams.has("auth")) return new Response(null, { status: isAdmin ? 204 : 401 });
    const data = await store.get("state", { type: "text" });
    return json(data || "null");
  }

  if (req.method === "POST") {
    if (!isAdmin) return json({ error: "unauthorized" }, 401);
    const body = await req.text();
    if (body.length > 4_000_000) return json({ error: "too large" }, 413);
    let parsed;
    try { parsed = JSON.parse(body); } catch { return json({ error: "bad json" }, 400); }
    if (!parsed || !Array.isArray(parsed.rows)) return json({ error: "missing rows" }, 400);
    await store.set("state", body);
    return json({ ok: true });
  }

  return json({ error: "method not allowed" }, 405);
};

export const config = { path: ["/api/data", "/api/photo"] };
