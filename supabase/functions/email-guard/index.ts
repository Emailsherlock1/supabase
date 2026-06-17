// EmailSherlock Email-Guard — Supabase "Before User Created" auth hook.
//
// Supabase POSTs each signup to this Edge Function before the user row is
// created. The function asks the EmailSherlock verify API whether the address
// is junk (disposable / undeliverable) and, based on your policy, either lets
// the signup through or rejects it.
//
// Contract (verified against the Supabase "Before User Created" hook docs):
//   request : { metadata: { ip_address, ... }, user: { email, app_metadata: { provider }, ... } }
//   allow   : 200 with `{}`
//   reject  : 4xx with `{ "error": { "message": string, "http_code": number } }`
//   signing : Standard Webhooks ("v1,whsec_<base64>"), secret from the Supabase
//             Auth Hooks dashboard. The hook runs before a JWT exists, so deploy
//             this function with `--no-verify-jwt`.
//
// Core principle (shared with the Symfony bundle): fail open. If the verify API
// times out, errors, or no key is configured, the signup is allowed and the
// reason is logged. Never let an API hiccup block a legitimate signup.

import { Webhook } from "https://esm.sh/standardwebhooks@1.0.0";

// ---------------------------------------------------------------------------
// Config (all from environment / Supabase function secrets)
// ---------------------------------------------------------------------------

const API_BASE_URL =
  Deno.env.get("EMAILSHERLOCK_API_BASE_URL") ?? "https://api.emailsherlock.com";
const API_KEY = Deno.env.get("EMAILSHERLOCK_API_KEY") ?? "";

// Which verify recommendations cause a reject. The API returns one of
// allow / deny / review. Default blocks only on `deny`; add `review` to also
// block role / catch-all / uncertain addresses. Policy belongs to you.
const BLOCK_ON = new Set(
  (Deno.env.get("EMAILSHERLOCK_BLOCK_ON") ?? "deny")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean),
);

// fail_open=true (default): on any error the signup is allowed. Set to "false"
// to fail closed (reject when the API can't give a verdict).
const FAIL_OPEN =
  (Deno.env.get("EMAILSHERLOCK_FAIL_OPEN") ?? "true").toLowerCase() !== "false";

const TIMEOUT_MS = Number(Deno.env.get("EMAILSHERLOCK_TIMEOUT_MS") ?? "800");

// Message shown to the rejected user. Keep it generic; do not leak the verdict.
const REJECT_MESSAGE =
  Deno.env.get("EMAILSHERLOCK_REJECT_MESSAGE") ??
  "That email address can't be used to sign up. Please use a different one.";

// Standard Webhooks secret from the Supabase Auth Hooks dashboard. When set,
// every request is signature-checked. Strongly recommended in production.
const HOOK_SECRET = Deno.env.get("EMAILSHERLOCK_HOOK_SECRET") ?? "";

// Opt-in, best-effort domain-only telemetry to the Guard analytics endpoint.
// Never sends the full address, only the domain. Off unless explicitly enabled.
const TELEMETRY =
  (Deno.env.get("EMAILSHERLOCK_GUARD_TELEMETRY") ?? "false").toLowerCase() ===
  "true";

const SPEC_VERSION = "1.1.0";
const LIB_VERSION = "0.1.0";

// ---------------------------------------------------------------------------
// Responses in the shape Supabase expects
// ---------------------------------------------------------------------------

const ALLOW = () =>
  new Response(JSON.stringify({}), {
    status: 200,
    headers: { "content-type": "application/json" },
  });

const REJECT = (message: string, httpCode = 400) =>
  new Response(JSON.stringify({ error: { message, http_code: httpCode } }), {
    status: httpCode,
    headers: { "content-type": "application/json" },
  });

// ---------------------------------------------------------------------------
// Verify call
// ---------------------------------------------------------------------------

type VerifyResult = {
  result?: string;
  disposable?: boolean;
  role?: boolean;
  catch_all?: boolean;
  decision?: { recommendation?: string; reasons?: string[] };
};

async function verify(email: string): Promise<VerifyResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(`${API_BASE_URL}/v1/verify/single`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "X-API-Key": API_KEY,
      },
      body: JSON.stringify({ email }),
      signal: controller.signal,
    });
    if (!res.ok) {
      throw new Error(`verify API returned ${res.status}`);
    }
    return (await res.json()) as VerifyResult;
  } finally {
    clearTimeout(timer);
  }
}

// Best-effort, fire-and-forget. Sends only the domain (no PII), matching the
// /v1/guard/events contract. Never throws into the request path.
function reportTelemetry(domain: string, recommendation: string, blocked: boolean) {
  if (!TELEMETRY || !API_KEY) return;
  const action = blocked ? "deny" : "allow";
  fetch(`${API_BASE_URL}/v1/guard/events`, {
    method: "POST",
    headers: { "content-type": "application/json", "X-API-Key": API_KEY },
    body: JSON.stringify({
      events: [
        {
          domain,
          verdict: recommendation,
          action,
          reasons: [],
          degraded: false,
          source: "supabase-auth-hook",
          integration: "supabase",
          lib_version: LIB_VERSION,
          spec_version: SPEC_VERSION,
        },
      ],
    }),
  }).catch(() => {
    /* telemetry must never affect the signup */
  });
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

Deno.serve(async (req) => {
  if (req.method !== "POST") {
    return REJECT("Method not allowed", 405);
  }

  const raw = await req.text();

  // Verify the Standard Webhooks signature when a secret is configured.
  if (HOOK_SECRET) {
    try {
      const headers = Object.fromEntries(req.headers);
      new Webhook(HOOK_SECRET).verify(raw, headers);
    } catch (_e) {
      // A bad signature is a real auth failure, not an API hiccup: reject it
      // regardless of fail-open. fail-open covers verify outages, not forgery.
      return REJECT("Invalid hook signature", 401);
    }
  }

  let payload: { user?: { email?: string } };
  try {
    payload = JSON.parse(raw);
  } catch {
    return FAIL_OPEN ? ALLOW() : REJECT("Malformed hook payload", 400);
  }

  const email = (payload.user?.email ?? "").trim();
  if (!email) {
    // No address to check; let Supabase's own validation handle it.
    return ALLOW();
  }
  const domain = email.includes("@") ? email.split("@").pop()!.toLowerCase() : "";

  if (!API_KEY) {
    console.warn("email-guard: EMAILSHERLOCK_API_KEY not set, allowing signup");
    return ALLOW();
  }

  try {
    const result = await verify(email);
    const recommendation = (result.decision?.recommendation ?? "review").toLowerCase();
    const blocked = BLOCK_ON.has(recommendation);

    reportTelemetry(domain, recommendation, blocked);

    if (blocked) {
      console.info(`email-guard: rejected ${domain} (${recommendation})`);
      return REJECT(REJECT_MESSAGE, 400);
    }
    return ALLOW();
  } catch (e) {
    // Fail open: a verify outage must not block a real user.
    console.warn(`email-guard: verify failed (${e}); fail_open=${FAIL_OPEN}`);
    return FAIL_OPEN ? ALLOW() : REJECT(REJECT_MESSAGE, 400);
  }
});
