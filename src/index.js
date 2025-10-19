// ============================================================================
// DURABLE OBJECT: IOC Storage
// ============================================================================
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
// CROWDSTRIKE FALCON INTEGRATION
// ============================================================================
class CrowdstrikeIntegration {
  constructor(env) {
    this.env = env;
    this.baseUrl = 'https://api.crowdstrike.com';
    this.tokenCache = null;
    this.tokenExpiry = null;
  }

  async getAccessToken() {
    // Check if we have a cached valid token
    if (this.tokenCache && this.tokenExpiry && Date.now() < this.tokenExpiry) {
      return this.tokenCache;
    }

    // Check KV cache first
    const cachedToken = await this.env.CTI_CACHE.get('crowdstrike_token', { type: 'json' });
    if (cachedToken && cachedToken.expiry > Date.now()) {
      this.tokenCache = cachedToken.token;
      this.tokenExpiry = cachedToken.expiry;
      return this.tokenCache;
    }

    // Get new token
    const response = await fetch(`${this.baseUrl}/oauth2/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
      },
      body: new URLSearchParams({
        client_id: this.env.CROWDSTRIKE_CLIENT_ID,
        client_secret: this.env.CROWDSTRIKE_CLIENT_SECRET,
        grant_type: 'client_credentials'
      })
    });

    if (!response.ok) {
      throw new Error(`Crowdstrike auth failed: ${response.status}`);
    }

    const data = await response.json();
    this.tokenCache = data.access_token;
    this.tokenExpiry = Date.now() + (data.expires_in * 1000) - 60000; // 1 min buffer

    // Cache in KV
    await this.env.CTI_CACHE.put('crowdstrike_token', JSON.stringify({
      token: this.tokenCache,
      expiry: this.tokenExpiry
    }), { expirationTtl: data.expires_in - 60 });

    return this.tokenCache;
  }

  async enrichIOC(indicator, type) {
    const token = await this.getAccessToken();

    // Determine the appropriate API endpoint based on type
    let endpoint, body;
    
    if (type === 'ip') {
      endpoint = '/indicators/entities/iocs/v1';
      body = JSON.stringify({
        type: 'ipv4',
        value: indicator
      });
    } else if (type === 'domain') {
      endpoint = '/indicators/entities/iocs/v1';
      body = JSON.stringify({
        type: 'domain',
        value: indicator
      });
    } else if (type === 'hash') {
      endpoint = '/indicators/entities/iocs/v1';
      body = JSON.stringify({
        type: 'sha256',
        value: indicator
      });
    } else {
      throw new Error('Unsupported indicator type');
    }

    const response = await fetch(`${this.baseUrl}${endpoint}`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Crowdstrike API error: ${response.status} - ${error}`);
    }

    return await response.json();
  }

  async searchDetections(indicator) {
    const token = await this.getAccessToken();

    const response = await fetch(`${this.baseUrl}/detects/queries/detects/v1?filter=behaviors.ioc_value:'${indicator}'`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    });

    if (!response.ok) {
      throw new Error(`Crowdstrike detection search failed: ${response.status}`);
    }

    return await response.json();
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
  const indicator = url.searchParams.get('indicator');
  const type = url.searchParams.get('type');
  const source = url.searchParams.get('source') || 'crowdstrike';

  if (!indicator || !type) {
    return new Response(JSON.stringify({ error: 'Missing indicator or type parameter' }), {
      status: 400,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }

  // Check cache first
  const cacheKey = `enrich:${source}:${indicator}`;
  const cached = await env.CTI_CACHE.get(cacheKey, { type: 'json' });
  
  if (cached) {
    return new Response(JSON.stringify({ ...cached, cached: true }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }

  // Enrich based on source
  let enrichmentData;
  
  if (source === 'crowdstrike') {
    const cs = new CrowdstrikeIntegration(env);
    const iocData = await cs.enrichIOC(indicator, type);
    const detections = await cs.searchDetections(indicator);
    
    enrichmentData = {
      indicator,
      type,
      source: 'crowdstrike',
      data: iocData,
      detections: detections.resources?.length || 0,
      timestamp: new Date().toISOString()
    };
  } else {
    return new Response(JSON.stringify({ error: 'Unsupported enrichment source' }), {
      status: 400,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }

  // Cache the result for 1 hour
  await env.CTI_CACHE.put(cacheKey, JSON.stringify(enrichmentData), { expirationTtl: 3600 });

  // Store in Durable Object
  const id = env.IOC_STORAGE.idFromName('global');
  const stub = env.IOC_STORAGE.get(id);
  await stub.fetch(new Request('https://dummy/store', {
    method: 'POST',
    body: JSON.stringify({
      indicator,
      type,
      enrichmentData,
      source
    })
  }));

  return new Response(JSON.stringify(enrichmentData), {
    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
  });
}