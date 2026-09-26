/**
 * Netra API Client
 * Seamlessly interfaces with Ingestion API (port 8000) and API Gateway (port 8080).
 */

import { authorizedFetch } from '@/lib/auth';

const getApiBase = (defaultPort) => {
  if (typeof window !== 'undefined') {
    const host = window.location.hostname || 'localhost';
    const proto = window.location.protocol || 'http:';
    return `${proto}//${host}:${defaultPort}`;
  }
  return `http://localhost:${defaultPort}`;
};

export const getIngestionBase = () => process.env.NEXT_PUBLIC_INGESTION_URL || getApiBase(8000);
export const getGatewayBase = () => process.env.NEXT_PUBLIC_GATEWAY_URL || getApiBase(8080);

/**
 * Raised when the backend pipeline is unreachable or rejects the submission.
 * The UI surfaces this instead of silently substituting fabricated results.
 */
export class BackendUnavailableError extends Error {
  constructor(message, cause) {
    super(message);
    this.name = 'BackendUnavailableError';
    this.cause = cause;
  }
}

/**
 * Probes the ingestion and gateway health endpoints.
 * Used to decide whether live analysis is possible before the user submits.
 */
export async function checkBackendHealth() {
  const probe = async (base) => {
    try {
      const res = await fetch(`${base}/health`, { signal: AbortSignal.timeout(3000) });
      if (!res.ok) return { online: false, status: 'degraded' };
      const body = await res.json();
      return { online: body.status === 'healthy', status: body.status || 'unknown', detail: body };
    } catch (err) {
      return { online: false, status: 'offline', detail: String(err) };
    }
  };

  const [ingestion, gateway] = await Promise.all([
    probe(getIngestionBase()),
    probe(getGatewayBase()),
  ]);

  return { ingestion, gateway, online: ingestion.online && gateway.online };
}

export async function ingestEmailText(rawEmail) {
  const base = getIngestionBase();
  let res;
  try {
    res = await authorizedFetch(`${base}/api/v1/ingest/text`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ raw_email: rawEmail }),
      signal: AbortSignal.timeout(15000),
    });
  } catch (err) {
    throw new BackendUnavailableError(
      `Ingestion service unreachable at ${base}. Start the pipeline with "docker compose up -d", or switch on Offline Demo Mode.`,
      err,
    );
  }

  if (!res.ok) {
    const detail = await res.text().catch(() => '');
    throw new BackendUnavailableError(
      `Ingestion service rejected the submission (HTTP ${res.status}). ${detail}`.trim(),
    );
  }

  return res.json();
}

export async function ingestEmailFile(file) {
  const base = getIngestionBase();
  const formData = new FormData();
  formData.append('file', file);

  let res;
  try {
    res = await authorizedFetch(`${base}/api/v1/ingest/file`, {
      method: 'POST',
      body: formData,
      signal: AbortSignal.timeout(20000),
    });
  } catch (err) {
    throw new BackendUnavailableError(
      `Ingestion service unreachable at ${base}. Start the pipeline with "docker compose up -d", or switch on Offline Demo Mode.`,
      err,
    );
  }

  if (!res.ok) {
    const detail = await res.text().catch(() => '');
    throw new BackendUnavailableError(
      `Ingestion service rejected the upload (HTTP ${res.status}). ${detail}`.trim(),
    );
  }

  return res.json();
}

export async function fetchReportsList() {
  const base = getGatewayBase();
  try {
    const res = await authorizedFetch(`${base}/api/v1/reports?limit=50`, {
      signal: AbortSignal.timeout(5000),
    });
    if (res.ok) {
      const data = await res.json();
      if (Array.isArray(data)) {
        return data;
      }
    }
  } catch (err) {
    console.warn('Error fetching reports from gateway:', err);
  }
  return [];
}

export async function fetchReportDetails(id) {
  if (!id) return null;
  const base = getGatewayBase();
  try {
    const res = await authorizedFetch(`${base}/api/v1/reports/${id}`, {
      signal: AbortSignal.timeout(5000),
    });
    if (res.ok) {
      return await res.json();
    }
  } catch (err) {
    console.warn(`Error fetching report ${id}:`, err);
  }
  return null;
}

/**
 * Polls API Gateway for the finalized report while backend microservices process the email.
 */
export async function pollReportDetails(id, maxAttempts = 12, intervalMs = 600) {
  if (!id) return null;
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const report = await fetchReportDetails(id);
    if (report && (report.email_id || report.classification || report.threat_assessment)) {
      return report;
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  return null;
}

/**
 * Canonical stage list, fetched from the gateway so the UI never invents stage names.
 * Falls back to the compiled-in sequence if the gateway is unreachable.
 */
export const FALLBACK_PIPELINE_STAGES = [
  { key: 'ingested', index: 1, label: 'Ingestion', layer: 1, service: 'ingestion' },
  { key: 'parsed', index: 2, label: 'MIME Parsing', layer: 2, service: 'parser' },
  { key: 'analyzed', index: 3, label: 'Analysis Engines', layer: 3, service: 'analyzer' },
  { key: 'scored', index: 4, label: 'Threat Scoring', layer: 4, service: 'threat_engine' },
  { key: 'enriched', index: 5, label: 'Threat Intel', layer: 5, service: 'threat_intel' },
  { key: 'correlated', index: 6, label: 'Graph Correlation', layer: 6, service: 'correlation' },
  { key: 'persisted', index: 7, label: 'Report Persistence', layer: 7, service: 'api_gateway' },
];

export async function fetchPipelineStages() {
  try {
    const res = await fetch(`${getGatewayBase()}/api/v1/pipeline/stages`, {
      signal: AbortSignal.timeout(4000),
    });
    if (res.ok) {
      const data = await res.json();
      if (Array.isArray(data.stages) && data.stages.length) return data.stages;
    }
  } catch (err) {
    console.warn('Could not fetch pipeline stage definitions:', err);
  }
  return FALLBACK_PIPELINE_STAGES;
}

/**
 * Subscribes to real pipeline stage transitions for an email over Server-Sent Events.
 *
 * Every `stage` callback corresponds to a Redis event published by the service that
 * actually processed the email, carrying that service's own measured latency —
 * there is no client-side simulation of progress.
 *
 * Returns a cancel function; callers must invoke it on unmount.
 */
export function streamPipelineEvents(emailId, { onStage, onDone, onError } = {}) {
  if (!emailId) {
    onError?.(new Error('Cannot stream pipeline events without an email id.'));
    return () => {};
  }

  const streamUrl = `${getGatewayBase()}/api/v1/pipeline/events/${encodeURIComponent(emailId)}`;
  let source;
  let closed = false;

  const close = () => {
    if (closed) return;
    closed = true;
    try {
      source?.close();
    } catch (err) {
      /* already closed */
    }
  };

  const attachListeners = (source) => {
    source.addEventListener('stage', (evt) => {
      try {
        onStage?.(JSON.parse(evt.data));
      } catch (err) {
        console.warn('Malformed pipeline stage frame:', err);
      }
    });

    source.addEventListener('done', (evt) => {
      let payload = {};
      try {
        payload = JSON.parse(evt.data);
      } catch (err) {
        /* payload is advisory only */
      }
      close();
      onDone?.(payload);
    });

    source.addEventListener('timeout', (evt) => {
      let payload = {};
      try {
        payload = JSON.parse(evt.data);
      } catch (err) {
        /* payload is advisory only */
      }
      close();
      onError?.(new Error(payload.message || 'Pipeline did not complete in time.'));
    });

    source.onerror = () => {
      // EventSource auto-reconnects; a closed stream after `done` is expected. A reconnect
      // would also fail, since the ticket was single-use.
      if (closed) return;
      close();
      onError?.(new BackendUnavailableError('Pipeline event stream disconnected.'));
    };
  };

  // EventSource cannot send an Authorization header, so trade the session token for a
  // single-use ticket first; the long-lived token never appears in a URL.
  (async () => {
    let ticket;
    try {
      const res = await authorizedFetch(`${streamUrl}/ticket`, { method: 'POST', signal: AbortSignal.timeout(5000) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      ticket = (await res.json()).ticket;
    } catch (err) {
      if (!closed) onError?.(new BackendUnavailableError('Could not authorise the pipeline event stream.', err));
      return;
    }
    if (closed) return;
    try {
      source = new EventSource(`${streamUrl}?ticket=${encodeURIComponent(ticket)}`);
    } catch (err) {
      onError?.(new BackendUnavailableError('Browser could not open the pipeline event stream.', err));
      return;
    }
    attachListeners(source);
  })();

  return close;
}

/**
 * Non-streaming fallback: fetch the recorded stage events for an email.
 * Used when EventSource is unavailable (older browsers, restrictive proxies).
 */
export async function fetchPipelineHistory(emailId) {
  if (!emailId) return null;
  try {
    const res = await authorizedFetch(
      `${getGatewayBase()}/api/v1/pipeline/events/${encodeURIComponent(emailId)}/history`,
      { signal: AbortSignal.timeout(5000) },
    );
    if (res.ok) return res.json();
  } catch (err) {
    console.warn(`Could not fetch pipeline history for ${emailId}:`, err);
  }
  return null;
}

/**
 * Fetches the Neo4j attack-infrastructure subgraph centred on one email.
 * Returns null when the graph is unavailable so callers can degrade gracefully
 * rather than render an empty diagram that implies "no shared infrastructure".
 */
export async function fetchEmailSubgraph(emailId) {
  if (!emailId) return null;
  try {
    const res = await authorizedFetch(`${getGatewayBase()}/api/v1/graph/${encodeURIComponent(emailId)}`, {
      signal: AbortSignal.timeout(8000),
    });
    if (res.ok) return res.json();
    if (res.status === 503) return { unavailable: true, reason: 'Neo4j is not reachable.' };
  } catch (err) {
    console.warn(`Could not fetch subgraph for ${emailId}:`, err);
  }
  return null;
}

/**
 * Resolves real-time IP Geolocation, ASN, and ISP data for email ingress IPs.
 */
export async function resolveIpGeolocation(ip) {
  if (!ip || typeof ip !== 'string') return null;
  const cleanIp = ip.trim();

  // Handle loopback or private ranges
  if (
    cleanIp === '127.0.0.1' ||
    cleanIp === '0.0.0.0' ||
    cleanIp.startsWith('10.') ||
    cleanIp.startsWith('192.168.') ||
    cleanIp.startsWith('172.16.') ||
    cleanIp.startsWith('172.17.') ||
    cleanIp.startsWith('172.18.')
  ) {
    return {
      ip: cleanIp,
      location: 'Internal Corporate Perimeter',
      city: 'Private Network',
      region: 'Intranet',
      country: 'Internal Subnet',
      countryCode: 'LAN',
      flag: '🔒',
      isp: 'Corporate Gateway',
      asn: 'Private BGP Transit',
      lat: 37.7749,
      lon: -122.4194,
    };
  }

  // 1. Try ipwho.is (Free HTTPS with SVG flag & ASN)
  try {
    const res = await fetch(`https://ipwho.is/${cleanIp}`, { signal: AbortSignal.timeout(4000) });
    if (res.ok) {
      const data = await res.json();
      if (data.success) {
        return {
          ip: cleanIp,
          location: `${data.city || data.region || 'Unknown City'}, ${data.country || 'Unknown Country'}`,
          city: data.city || data.region || 'Unknown City',
          region: data.region || '',
          country: data.country || 'Unknown Country',
          countryCode: data.country_code || 'UN',
          flag: data.flag?.emoji || '🌐',
          isp: data.connection?.isp || data.connection?.org || 'Internet Service Provider',
          asn: data.connection?.asn ? `AS${data.connection.asn} ${data.connection.org || ''}`.trim() : 'BGP Transit',
          lat: data.latitude || 37.7749,
          lon: data.longitude || -122.4194,
        };
      }
    }
  } catch (err) {
    console.warn('ipwho.is lookup failed, trying fallback:', err);
  }

  // 2. Fallback to ip-api.com
  try {
    const res = await fetch(`http://ip-api.com/json/${cleanIp}`, { signal: AbortSignal.timeout(3500) });
    if (res.ok) {
      const data = await res.json();
      if (data.status === 'success') {
        return {
          ip: cleanIp,
          location: `${data.city}, ${data.country}`,
          city: data.city,
          region: data.regionName,
          country: data.country,
          countryCode: data.countryCode,
          flag: '🌐',
          isp: data.isp || data.org || 'Internet Service Provider',
          asn: data.as || 'BGP Transit',
          lat: data.lat,
          lon: data.lon,
        };
      }
    }
  } catch (err) {
    console.warn('ip-api.com fallback failed:', err);
  }

  return null;
}
