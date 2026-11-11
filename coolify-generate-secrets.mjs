#!/usr/bin/env node
// Génère les secrets de production de Mike pour l'écran « Environment
// Variables » de Coolify. Aucune dépendance : `node coolify-generate-secrets.mjs`.
//
// Les deux clés Supabase sont des JWT signés avec SUPABASE_JWT_SECRET :
// elles vont ensemble. Régénérer l'une impose de régénérer les trois, et de
// redémarrer auth, rest et backend.
import { createHmac, randomBytes } from "node:crypto";

const hex = (n = 32) => randomBytes(n).toString("hex");
const b64url = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");

const jwtSecret = hex(32);
const now = Math.floor(Date.now() / 1000);
const tenYears = 10 * 365 * 24 * 3600;

function supabaseKey(role) {
  const head = b64url({ alg: "HS256", typ: "JWT" });
  const body = b64url({ role, iss: "supabase", iat: now, exp: now + tenYears });
  const sig = createHmac("sha256", jwtSecret).update(`${head}.${body}`).digest("base64url");
  return `${head}.${body}.${sig}`;
}

const out = {
  SUPABASE_JWT_SECRET: jwtSecret,
  SUPABASE_PUBLISHABLE_KEY: supabaseKey("anon"),
  SUPABASE_SECRET_KEY: supabaseKey("service_role"),
  POSTGRES_PASSWORD: hex(24),
  STORAGE_ACCESS_KEY: hex(10),
  STORAGE_SECRET_KEY: hex(24),
  DOWNLOAD_SIGNING_SECRET: hex(32),
  USER_API_KEYS_ENCRYPTION_SECRET: hex(32),
  MCP_CONNECTORS_ENCRYPTION_SECRET: hex(32),
};

for (const [k, v] of Object.entries(out)) console.log(`${k}=${v}`);
