// Minimal CrowdStrike Falcon Intel client for Cloudflare Workers
// Uses Cloudflare KV (CTI_CACHE) to cache OAuth tokens securely.

function getCrowdStrikeBaseUrl(env) {
  const configured = (env && (env.CROWDSTRIKE_BASE_URL || env.CROWDSTRIKE_API_BASE)) ? (env.CROWDSTRIKE_BASE_URL || env.CROWDSTRIKE_API_BASE) : "https://api.crowdstrike.com";
  try {
    const url = new URL(configured);
    return `${url.origin}`; // strip any trailing path
  } catch {
    return "https://api.crowdstrike.com";
  }
}

export async function getCrowdStrikeToken(env) {
  if (!env || !env.CROWDSTRIKE_CLIENT_ID || !env.CROWDSTRIKE_CLIENT_SECRET) {
    throw new Error("CrowdStrike credentials are not configured in environment variables.");
  }

  // Try KV cache
  try {
    if (env.CTI_CACHE && env.CTI_CACHE.get) {
      const cachedToken = await env.CTI_CACHE.get("crowdstrike_oauth_token");
      if (cachedToken) return cachedToken;
    }
  } catch (kvReadError) {
    // Non-fatal: fall through to fetch a fresh token
    console.warn("KV read failed for CrowdStrike token:", kvReadError?.message || kvReadError);
  }

  const formBody = new URLSearchParams();
  formBody.set("client_id", env.CROWDSTRIKE_CLIENT_ID);
  formBody.set("client_secret", env.CROWDSTRIKE_CLIENT_SECRET);

  const tokenBase = getCrowdStrikeBaseUrl(env);
  const tokenResponse = await fetch(`${tokenBase}/oauth2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: formBody.toString(),
    signal: AbortSignal.timeout(10_000)
  });

  const tokenJson = await safeReadJson(tokenResponse);
  if (!tokenResponse.ok) {
    throw new Error(`CrowdStrike token request failed: HTTP ${tokenResponse.status} ${JSON.stringify(tokenJson)}`);
  }

  const accessToken = tokenJson?.access_token;
  const expiresInSeconds = Number(tokenJson?.expires_in || 1800);
  if (!accessToken) throw new Error("CrowdStrike token response missing access_token");

  // Cache with conservative TTL (90% of real)
  const ttlSeconds = Math.max(60, Math.floor(expiresInSeconds * 0.9));
  try {
    if (env.CTI_CACHE && env.CTI_CACHE.put) {
      await env.CTI_CACHE.put("crowdstrike_oauth_token", accessToken, { expirationTtl: ttlSeconds });
    }
  } catch (kvWriteError) {
    console.warn("KV write failed for CrowdStrike token:", kvWriteError?.message || kvWriteError);
  }

  return accessToken;
}

export async function queryCrowdStrikeIndicator(env, indicatorValue) {
  const sanitizedIndicator = sanitizeIndicator(indicatorValue);
  if (!sanitizedIndicator) {
    throw new Error("Invalid or empty indicator value.");
  }

  const accessToken = await getCrowdStrikeToken(env);

  // Indicators endpoint; exact match on indicator
  const intelBase = `${getCrowdStrikeBaseUrl(env)}/intel/combined/indicators/v1`;
  const params = new URLSearchParams();
  params.set("filter", `indicator:'${encodeIndicatorForFilter(sanitizedIndicator)}'`);
  params.set("limit", "5");

  const indicatorsResponse = await fetch(`${intelBase}?${params.toString()}`, {
    method: "GET",
    headers: {
      "Authorization": `Bearer ${accessToken}`,
      "Accept": "application/json"
    },
    signal: AbortSignal.timeout(15_000)
  });

  const rawJson = await safeReadJson(indicatorsResponse);
  if (!indicatorsResponse.ok) {
    const traceId = rawJson?.meta?.trace_id || rawJson?.meta?.traceId || "unknown-trace";
    const firstErr = Array.isArray(rawJson?.errors) && rawJson.errors.length ? rawJson.errors[0] : null;
    const reason = firstErr?.message || firstErr?.detail || "authorization failed";
    const code = firstErr?.code || indicatorsResponse.status;
    // Provide actionable detail without leaking secrets
    const hint = (code === 403)
      ? "Check that your API key has Falcon Intelligence READ permissions and that CROWDSTRIKE_BASE_URL matches your cloud (e.g., https://api.us-2.crowdstrike.com)."
      : "See CrowdStrike API docs for required scopes and region hostnames.";
    throw new Error(`CrowdStrike indicators request failed: HTTP ${indicatorsResponse.status} (code ${code}) reason='${reason}' trace_id='${traceId}'. ${hint}`);
  }

  const items = Array.isArray(rawJson?.resources) ? rawJson.resources : [];
  const normalized = items.map(normalizeCrowdStrikeResource);

  return { source: "crowdstrike", raw: rawJson, results: normalized };
}

// ---------- helpers ----------
function sanitizeIndicator(indicatorValue) {
  if (typeof indicatorValue !== "string") return "";
  const trimmed = indicatorValue.trim();
  if (trimmed.length === 0 || trimmed.length > 2048) return "";
  return trimmed;
}

function encodeIndicatorForFilter(indicatorValue) {
  // Filter uses single-quoted literal; escape any single quotes.
  return indicatorValue.replace(/'/g, "\\'");
}

async function safeReadJson(response) {
  try { return await response.json(); } catch { return { error: "non-json-response" }; }
}

function normalizeCrowdStrikeResource(resource) {
  const indicator = resource?.indicator || "";
  const firstSeen = resource?.first_seen || null;
  const lastSeen = resource?.last_seen || null;
  const type = resource?.type || resource?.labels?.[0] || "unknown";
  const maliciousConfidence = resource?.malicious_confidence || resource?.relations?.confidence || "unknown";
  const threatTypes = Array.isArray(resource?.threat_types) ? resource.threat_types : [];
  const actors = Array.isArray(resource?.actors) ? resource.actors : [];

  return {
    indicator,
    type,
    firstSeen,
    lastSeen,
    maliciousConfidence,
    threatTypes,
    actors,
    sources: resource?.reports || [],
    raw: resource
  };
}