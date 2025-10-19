// ============================================================================
// DURABLE OBJECT: IOC Storage
// ============================================================================
import { queryCrowdStrikeIndicator } from "./integrations/crowdstrike";
import { fetchSplunkThreatIntel } from "./integrations/splunk";

export class IOCStorage {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request) {
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      if (path === '/store' && request.method === 'POST') {
        return await this.storeIOC(request);
      } else if (path === '/store-batch' && request.method === 'POST') {
        return await this.storeBatch(request);
      } else if (path === '/get' && request.method === 'GET') {
        return await this.getIOC(url.searchParams.get('indicator'));
      } else if (path === '/list' && request.method === 'GET') {
        return await this.listIOCs(url.searchParams);
      } else if (path === '/delete' && request.method === 'DELETE') {
        return await this.deleteIOC(url.searchParams.get('indicator'));
      }

      return new Response('Not Found', { status: 404 });
    } catch (error) {
      return new Response(JSON.stringify({ error: error.message }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }

  async storeIOC(request) {
    const ioc = await request.json();
    
    // Validate required fields
    if (!ioc.indicator || !ioc.type) {
      return new Response(JSON.stringify({ error: 'Missing required fields' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Add metadata
    ioc.id = crypto.randomUUID();
    ioc.timestamp = new Date().toISOString();
    ioc.lastUpdated = ioc.timestamp;

    // Store in Durable Object storage
    await this.state.storage.put(`ioc:${ioc.indicator}`, ioc);

    // Update index for listing
    const index = await this.state.storage.get('ioc_index') || [];
    if (!index.includes(ioc.indicator)) {
      index.push(ioc.indicator);
      await this.state.storage.put('ioc_index', index);
    }

    return new Response(JSON.stringify({ success: true, ioc }), {
      status: 201,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  async storeBatch(request) {
    const payload = await request.json();
    const items = Array.isArray(payload?.items) ? payload.items : [];

    if (items.length === 0) {
      return new Response(JSON.stringify({ error: 'No items provided' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const index = (await this.state.storage.get('ioc_index')) || [];
    let storedCount = 0;

    for (const entry of items) {
      const indicatorValue = entry?.indicator;
      const indicatorType = entry?.type;
      if (!indicatorValue || !indicatorType) continue;

      const ioc = {
        id: crypto.randomUUID(),
        indicator: indicatorValue,
        type: indicatorType,
        enrichmentData: entry?.enrichmentData ?? null,
        source: entry?.source ?? 'unknown',
        timestamp: new Date().toISOString(),
        lastUpdated: new Date().toISOString()
      };

      await this.state.storage.put(`ioc:${indicatorValue}`, ioc);
      if (!index.includes(indicatorValue)) {
        index.push(indicatorValue);
      }
      storedCount++;
    }

    await this.state.storage.put('ioc_index', index);

    return new Response(JSON.stringify({ success: true, stored: storedCount }), {
      status: 201,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  async getIOC(indicator) {
    if (!indicator) {
      return new Response(JSON.stringify({ error: 'Indicator required' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const ioc = await this.state.storage.get(`ioc:${indicator}`);
    
    if (!ioc) {
      return new Response(JSON.stringify({ error: 'IOC not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response(JSON.stringify(ioc), {
      headers: { 'Content-Type': 'application/json' }
    });
  }

  async listIOCs(params) {
    const type = params.get('type');
    const limit = parseInt(params.get('limit') || '100');
    const offset = parseInt(params.get('offset') || '0');

    const index = await this.state.storage.get('ioc_index') || [];
    const indicators = index.slice(offset, offset + limit);

    const iocs = [];
    for (const indicator of indicators) {
      const ioc = await this.state.storage.get(`ioc:${indicator}`);
      if (ioc && (!type || ioc.type === type)) {
        iocs.push(ioc);
      }
    }

    return new Response(JSON.stringify({
      iocs,
      total: index.length,
      offset,
      limit
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  }

  async deleteIOC(indicator) {
    if (!indicator) {
      return new Response(JSON.stringify({ error: 'Indicator required' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    await this.state.storage.delete(`ioc:${indicator}`);
    
    const index = await this.state.storage.get('ioc_index') || [];
    const newIndex = index.filter(i => i !== indicator);
    await this.state.storage.put('ioc_index', newIndex);

    return new Response(JSON.stringify({ success: true }), {
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// ============================================================================
// MAIN WORKER
// ============================================================================
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS headers
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      // Route to appropriate handler
      if (path.startsWith('/api/ioc')) {
        return await handleIOCRequest(request, env, corsHeaders);
      } else if (path.startsWith('/api/enrich')) {
        return await handleEnrichRequest(request, env, corsHeaders);
      } else if (path === '/api/intel/splunk') {
        // Fetch threat intel from Splunk and (optionally) store to IOC DO
        try {
          const searchParam = url.searchParams.get('search');
          const effectiveSearch = searchParam || env?.SPLUNK_SEARCH || '';
          if (!effectiveSearch) {
            return new Response(JSON.stringify({ error: "Missing 'search' parameter and SPLUNK_SEARCH not set" }), {
              status: 400,
              headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
          }

          const intel = await fetchSplunkThreatIntel(env, effectiveSearch);

          // Best-effort batch store into DO so they appear in /api/ioc/list
          try {
            if (Array.isArray(intel.results) && intel.results.length) {
              const id = env.IOC_STORAGE.idFromName('global');
              const stub = env.IOC_STORAGE.get(id);
              await stub.fetch(new Request('https://internal/store-batch', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                  source: 'splunk',
                  items: intel.results.map((item) => ({
                    indicator: item.indicator,
                    type: item.type,
                    enrichmentData: item
                  }))
                })
              }));
            }
          } catch (doError) {
            console.warn('DO batch store failed:', doError?.message || doError);
          }

          return new Response(JSON.stringify(intel), {
            status: 200,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          });
        } catch (splunkError) {
          console.error('Splunk intel error:', splunkError?.stack || splunkError);
          return new Response(JSON.stringify({ error: String(splunkError?.message || splunkError) }), {
            status: 502,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          });
        }
      } else if (path === '/api/health') {
        return new Response(JSON.stringify({ status: 'healthy', timestamp: new Date().toISOString() }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      return new Response('Not Found', { status: 404, headers: corsHeaders });
    } catch (error) {
      return new Response(JSON.stringify({ error: error.message }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
  }
};

function jsonResponse(payload, statusCode = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(payload), {
    status: statusCode,
    headers: { "Content-Type": "application/json", ...extraHeaders }
  });
}

// ============================================================================
// REQUEST HANDLERS
// ============================================================================
async function handleIOCRequest(request, env, corsHeaders) {
  const url = new URL(request.url);
  
  // Get Durable Object instance
  const id = env.IOC_STORAGE.idFromName('global');
  const stub = env.IOC_STORAGE.get(id);

  // Forward request to Durable Object
  const doUrl = new URL(request.url);
  doUrl.pathname = doUrl.pathname.replace('/api/ioc', '');
  
  const doRequest = new Request(doUrl.toString(), request);
  const response = await stub.fetch(doRequest);

  // Add CORS headers to response
  const newResponse = new Response(response.body, response);
  Object.entries(corsHeaders).forEach(([key, value]) => {
    newResponse.headers.set(key, value);
  });

  return newResponse;
}

async function handleEnrichRequest(request, env, corsHeaders) {
  const url = new URL(request.url);
  const indicatorRaw = url.searchParams.get('value') || url.searchParams.get('indicator') || '';
  const indicator = (indicatorRaw || '').trim();
  const requestedType = (url.searchParams.get('type') || '').trim();
  const source = (url.searchParams.get('source') || 'crowdstrike').toLowerCase();

  if (!indicator) {
    return jsonResponse({ error: 'Missing indicator value (use ?value= or ?indicator=)' }, 400, { ...corsHeaders });
  }

  // Check cache first
  const cacheKey = `enrich:${source}:${indicator}`;
  const cached = await env.CTI_CACHE.get(cacheKey, { type: 'json' });
  
  if (cached) {
    return new Response(JSON.stringify({ ...cached, cached: true }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }

  let enrichmentData;

  if (source === 'crowdstrike') {
    try {
      const queryResult = await queryCrowdStrikeIndicator(env, indicator);
      const first = Array.isArray(queryResult.results) && queryResult.results.length > 0 ? queryResult.results[0] : null;
      const normalizedType = requestedType || (first?.type || 'unknown');

      enrichmentData = {
        indicator,
        type: normalizedType,
        source: 'crowdstrike',
        results: queryResult.results,
        timestamp: new Date().toISOString()
      };
    } catch (crowdstrikeError) {
      console.error('CrowdStrike enrich error:', crowdstrikeError?.stack || crowdstrikeError);
      return jsonResponse({ error: 'CrowdStrike enrich failed' }, 502, { ...corsHeaders });
    }
  } else {
    return jsonResponse({ error: 'Unsupported enrichment source' }, 400, { ...corsHeaders });
  }

  try {
    await env.CTI_CACHE.put(cacheKey, JSON.stringify(enrichmentData), { expirationTtl: 3600 });
  } catch (cacheError) {
    console.warn('KV put failed for enrichment cache:', cacheError?.message || cacheError);
  }

  // Store in Durable Object (best-effort)
  try {
    const id = env.IOC_STORAGE.idFromName('global');
    const stub = env.IOC_STORAGE.get(id);
    await stub.fetch(new Request('https://internal/store', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ indicator, type: enrichmentData.type, enrichmentData, source })
    }));
  } catch (doError) {
    console.warn('DO store failed:', doError?.message || doError);
  }

  return jsonResponse(enrichmentData, 200, { ...corsHeaders });
}