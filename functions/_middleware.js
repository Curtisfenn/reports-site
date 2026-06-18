// Cloudflare Pages Functions middleware — per-company HTTP Basic Auth.
// GitHub-deploy variant: password hashes are imported from ../_auth/passwords.js,
// which lives OUTSIDE the build output dir (_site) and is therefore never served
// as a static asset. The publish flow regenerates that module on each publish.
import { PASSWORDS } from "../_auth/passwords.js";

const encoder = new TextEncoder();

async function sha256Hex(str) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(str));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
}

function unauthorized(realm) {
  return new Response("Authentication required.", {
    status: 401,
    headers: { "WWW-Authenticate": `Basic realm="${realm}", charset="UTF-8"` },
  });
}

export async function onRequest(context) {
  const { request, next } = context;
  const url = new URL(request.url);

  const segments = url.pathname.split("/").filter(Boolean);
  const slug = segments[0] || "";
  if (!slug) return next(); // bare domain has nothing sensitive

  const expectedHash = (PASSWORDS || {})[slug];
  if (!expectedHash) return next(); // unknown slug -> let Pages 404 it

  const header = request.headers.get("Authorization") || "";
  if (!header.startsWith("Basic ")) return unauthorized(slug);

  let decoded = "";
  try {
    decoded = atob(header.slice(6));
  } catch (e) {
    return unauthorized(slug);
  }
  const idx = decoded.indexOf(":");
  const password = idx === -1 ? "" : decoded.slice(idx + 1);

  const providedHash = await sha256Hex(password);
  if (!safeEqual(providedHash, expectedHash)) return unauthorized(slug);

  return next();
}
