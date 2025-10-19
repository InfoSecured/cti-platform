// src/integrations/splunk.js
// Splunk Cloud (Splunk ES) integration for fetching threat intel via Search Export API
// Env:
//   SPLUNK_BASE_URL (e.g., https://your-stack.splunkcloud.com:8089)
//   SPLUNK_TOKEN (secret, Splunk Cloud auth token)
//   SPLUNK_SEARCH (optional, e.g., "| savedsearch cti_indicators_export")

export async function splunkSearchExport(env, searchQuery) {
  const baseUrl = getBaseUrl(env);
  const token = getToken(env);
  const query = ensureSearchPrefix(searchQuery);

  const form = new URLSearchParams();
  form.set("search", query);
  form.set("output_mode", "json");

  const response = await fetch(`${baseUrl}/services/search/jobs/export`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${token}`,
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: form.toString(),
    signal: AbortSignal.timeout(20000)
  });

  const bodyText = await response.text();
  if (!response.ok) {
    throw new Error(`Splunk export failed: HTTP ${response.status} body='${truncate(bodyText, 800)}'`);
  }

  // Export returns JSON lines (one JSON object per line)
  const results = [];
  for (const line of bodyText.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed?.result) results.push(parsed.result);
    } catch {
      // ignore non-JSON lines
    }
  }
  return results;
}

export async function fetchSplunkThreatIntel(env, searchQuery) {
  const raw = await splunkSearchExport(env, searchQuery);
  const normalized = raw.map((row) => normalizeRow(row));
  return { source: "splunk", results: normalized };
}

// ------------- helpers -------------
function getBaseUrl(env) {
  const raw = env?.SPLUNK_BASE_URL || "";
  if (!raw) throw new Error("SPLUNK_BASE_URL is not configured");
  try { return new URL(raw).origin; } catch { throw new Error("SPLUNK_BASE_URL is invalid"); }
}
function getToken(env) {
  const token = env?.SPLUNK_TOKEN || "";
  if (!token) throw new Error("SPLUNK_TOKEN is not configured");
  return token;
}
function ensureSearchPrefix(query) {
  const sanitized = String(query || "").trim();
  if (sanitized.length === 0) throw new Error("Empty SPL passed to Splunk search");
  return sanitized.startsWith("search ") || sanitized.startsWith("|") ? sanitized : `search ${sanitized}`;
}
function truncate(value, maxLen) {
  const str = String(value || "");
  return str.length > maxLen ? str.slice(0, maxLen) + "…" : str;
}
function inferType(indicatorValue) {
  const v = String(indicatorValue || "").trim();
  if (/^[0-9a-fA-F]{64}$/.test(v)) return "sha256";
  if (/^[0-9a-fA-F]{40}$/.test(v)) return "sha1";
  if (/^[0-9a-fA-F]{32}$/.test(v)) return "md5";
  if (/^(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)){3}$/.test(v)) return "ip";
  if (/^(?:https?:\/\/)?[\w.-]+\.[A-Za-z]{2,}.*$/.test(v)) {
    return /^https?:/i.test(v) || /\/.+/.test(v) ? "url" : "domain";
  }
  return "unknown";
}
function normalizeRow(row) {
  const indicator = row.indicator ?? row.ioc ?? row.value ?? row.indicator_value ?? "";
  const type = row.type ?? row.ioc_type ?? inferType(indicator);
  const source = row.source ?? row.feed ?? row.vendor ?? "splunk";
  const confidence = row.confidence ?? row.conf ?? null;
  const validUntil = row.valid_until ?? row.validUntil ?? row.expiration ?? null;
  return { indicator, type, source, confidence, validUntil, raw: row };
}