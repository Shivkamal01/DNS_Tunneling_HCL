import axios from 'axios';

const API_BASE = process.env.REACT_APP_API_URL || 'http://127.0.0.1:8000';
const DEFAULT_TIMEOUT = 7000;

const client = axios.create({ baseURL: API_BASE, timeout: DEFAULT_TIMEOUT });

/**
 * Normalise backend errors into a single string the UI can display.
 *
 * The API returns {"error": {"message", "detail"}} for application, validation,
 * and routing failures. The {"detail": ...} branches are kept for older builds
 * and reverse proxies that synthesise their own error body.
 */
export function describeError(error) {
  const payload = error?.response?.data;
  if (payload?.error?.message) {
    return payload.error.detail
      ? `${payload.error.message}: ${payload.error.detail}`
      : payload.error.message;
  }
  if (typeof payload?.detail === 'string') return payload.detail;
  if (Array.isArray(payload?.detail) && payload.detail[0]?.msg) return payload.detail[0].msg;
  if (error?.code === 'ECONNABORTED') return 'Request timed out';
  if (error?.code === 'ERR_NETWORK' || error?.message === 'Network Error') {
    return 'Cannot reach the detection API';
  }
  return error?.message || 'Unexpected error';
}

/**
 * Sample data used only when the backend is unreachable, so the dashboard
 * still demonstrates the layout. Scores match what utils.evaluate_risk()
 * produces for these hostnames — they are not decorative numbers.
 */
export const FALLBACK_DEMO_ALERTS = [
  {
    id: 1,
    domain: 'mjqwq3dmnfsdgnbwmy2dsnzyhjrgk4tf.evil-c2.net',
    source_ip: '192.168.20.105',
    severity: 'CRITICAL',
    risk_score: 91,
    qtype_name: 'TXT',
    entropy: 4.12,
    entropy_ratio: 0.82,
    query_length: 45,
    subdomain_length: 32,
    max_label_length: 32,
    hex_ratio: 0.28,
    base32_foreign_ratio: 0.0,
    vowel_ratio: 0.0,
    consonant_run: 9,
    est_payload_bytes: 20,
    encoding: 'base32',
    detection_reason: 'Label decodes as base32 to binary data',
    indicator_list: [
      'Elevated label length (32 chars)',
      'High entropy payload (H=4.12, 82% of ceiling)',
      'Label decodes as base32 to binary data (34% printable)',
      'Consonant run of 9 characters (no natural word shape)',
      'TXT record query with extended payload',
    ],
    status: 'OPEN',
    analyst_notes: '',
    created_at: new Date(Date.now() - 3 * 60000).toISOString(),
  },
  {
    id: 2,
    domain: 'dnscat.fa73b92c4e1198501234abcd.malicious-tunnel.com',
    source_ip: '192.168.20.105',
    severity: 'CRITICAL',
    risk_score: 84,
    qtype_name: 'TXT',
    entropy: 4.03,
    entropy_ratio: 0.82,
    query_length: 52,
    subdomain_length: 31,
    max_label_length: 31,
    hex_ratio: 0.9,
    base32_foreign_ratio: 0.23,
    vowel_ratio: 0.27,
    consonant_run: 5,
    est_payload_bytes: 15,
    encoding: 'hex',
    detection_reason: 'Signature match: dnscat2 C2 subdomain',
    indicator_list: [
      'Elevated label length (31 chars)',
      'High entropy payload (H=4.03, 82% of ceiling)',
      'Hexadecimal-dominant payload (90% hex characters)',
      'TXT record query with extended payload',
      'Signature match: dnscat2 C2 subdomain',
    ],
    status: 'OPEN',
    analyst_notes: '',
    created_at: new Date(Date.now() - 9 * 60000).toISOString(),
  },
  {
    id: 3,
    domain: '7365637265742d646174612d64756d702d3031.c2-command.org',
    source_ip: '192.168.10.88',
    severity: 'HIGH',
    risk_score: 64,
    qtype_name: 'TXT',
    entropy: 3.06,
    entropy_ratio: 0.59,
    query_length: 51,
    subdomain_length: 38,
    max_label_length: 38,
    hex_ratio: 1.0,
    base32_foreign_ratio: 0.13,
    vowel_ratio: 0.0,
    consonant_run: 5,
    est_payload_bytes: 19,
    encoding: 'hex',
    detection_reason: 'Pure hexadecimal label 38 chars long (Iodine-style encoding)',
    indicator_list: [
      'Elevated label length (38 chars)',
      'Pure hexadecimal label 38 chars long (Iodine-style encoding)',
      'Vowel deficit (0% vowels)',
      'TXT record query with extended payload',
    ],
    status: 'INVESTIGATING',
    analyst_notes: 'Host 192.168.10.88 confirmed beaconing. EDR isolation requested.',
    created_at: new Date(Date.now() - 21 * 60000).toISOString(),
  },
  {
    id: 4,
    domain: '4g6d8e0f1g2h3j4k5l6m7n8p9q0r1s2t.tunnel-endpoint.biz',
    source_ip: '10.0.5.99',
    severity: 'HIGH',
    risk_score: 53,
    qtype_name: 'CNAME',
    entropy: 4.56,
    entropy_ratio: 0.91,
    query_length: 52,
    subdomain_length: 32,
    max_label_length: 32,
    hex_ratio: 0.59,
    base32_foreign_ratio: 0.22,
    vowel_ratio: 0.06,
    consonant_run: 4,
    est_payload_bytes: 20,
    encoding: 'ascii',
    detection_reason: 'Near-maximal entropy for payload length',
    indicator_list: [
      'Elevated label length (32 chars)',
      'Near-maximal entropy for payload length (H=4.56, 91% of ceiling)',
      'Vowel deficit (6% vowels)',
      'Long CNAME chain with payload-sized label',
    ],
    status: 'INVESTIGATING',
    analyst_notes: '',
    created_at: new Date(Date.now() - 40 * 60000).toISOString(),
  },
  {
    id: 5,
    domain: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.sha256.digicert.com',
    source_ip: '10.0.2.14',
    severity: 'MEDIUM',
    risk_score: 37,
    qtype_name: 'A',
    entropy: 3.81,
    entropy_ratio: 0.73,
    query_length: 82,
    subdomain_length: 64,
    max_label_length: 64,
    hex_ratio: 0.97,
    base32_foreign_ratio: 0.27,
    vowel_ratio: 0.29,
    consonant_run: 4,
    est_payload_bytes: 32,
    encoding: 'hex',
    detection_reason: 'Excessive label length (64 chars)',
    indicator_list: [
      'Excessive label length (64 chars)',
      'Hexadecimal-dominant payload (97% hex characters)',
    ],
    status: 'FALSE POSITIVE',
    analyst_notes: 'Certificate transparency hostname — benign by design. Whitelist recommended.',
    created_at: new Date(Date.now() - 70 * 60000).toISOString(),
  },
  {
    id: 6,
    domain: 'xghrtzqplmkbv.darknet-relay.info',
    source_ip: '192.168.10.15',
    severity: 'LOW',
    risk_score: 20,
    qtype_name: 'A',
    entropy: 3.7,
    entropy_ratio: 1.0,
    query_length: 33,
    subdomain_length: 13,
    max_label_length: 13,
    hex_ratio: 0.08,
    base32_foreign_ratio: 0.0,
    vowel_ratio: 0.0,
    consonant_run: 4,
    est_payload_bytes: 13,
    encoding: 'base32',
    detection_reason: 'Dense but short label set (H=3.70)',
    indicator_list: ['Dense but short label set (H=3.70)'],
    status: 'OPEN',
    analyst_notes: '',
    created_at: new Date(Date.now() - 120 * 60000).toISOString(),
  },
];

const request = async (config) => {
  const response = await client.request(config);
  return response.data;
};

export const api = {
  getAlerts: (params = {}) => request({ url: '/api/alerts', method: 'GET', params }),

  getAlertDetail: (id) => request({ url: `/api/alerts/${id}`, method: 'GET', timeout: 5000 }),

  updateAlertStatus: (id, status, notes = null) =>
    request({
      url: `/api/alerts/${id}/status`,
      method: 'PUT',
      data: { status, analyst_notes: notes },
      timeout: 5000,
    }),

  getIncidents: (params = {}) => request({ url: '/api/incidents', method: 'GET', params }),

  updateIncident: (id, payload) =>
    request({ url: `/api/incidents/${id}`, method: 'PUT', data: payload, timeout: 5000 }),

  getMetrics: () => request({ url: '/api/metrics', method: 'GET', timeout: 6000 }),

  getQueries: (limit = 60) => request({ url: '/api/queries', method: 'GET', params: { limit } }),

  simulateTraffic: (scenario = 'all', count = 5) =>
    request({ url: '/api/simulate', method: 'POST', data: { scenario, count }, timeout: 9000 }),

  triggerZeekIngest: () =>
    request({ url: '/api/ingest/zeek', method: 'POST', data: {}, timeout: 20000 }),

  triggerPcapIngest: () =>
    request({ url: '/api/ingest/pcap', method: 'POST', data: {}, timeout: 20000 }),

  getWhitelist: () => request({ url: '/api/whitelist', method: 'GET', timeout: 5000 }),

  addWhitelist: (domainPattern, reason) =>
    request({
      url: '/api/whitelist',
      method: 'POST',
      data: { domain_pattern: domainPattern, reason },
      timeout: 5000,
    }),

  removeWhitelist: (pattern) =>
    request({
      url: `/api/whitelist/${encodeURIComponent(pattern)}`,
      method: 'DELETE',
      timeout: 5000,
    }),

  analyzeDomain: (domain, queryType = 1) =>
    request({
      url: '/api/analyze',
      method: 'POST',
      params: { domain, query_type: queryType },
      timeout: 5000,
    }),

  getExportUrl: (format = 'csv') => `${API_BASE}/api/export?format=${format}`,
};

export { API_BASE };
