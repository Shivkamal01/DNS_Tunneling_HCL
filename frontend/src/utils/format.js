/**
 * Small formatting helpers shared by the console views.
 *
 * Keeping these in one place stops the table, drawer, and incident queue from
 * disagreeing about how a timestamp or an SLA is rendered.
 */

export const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

export function severityOf(value) {
  const normalized = String(value || 'LOW').toUpperCase();
  return SEVERITY_ORDER.includes(normalized) ? normalized : 'LOW';
}

export function toDate(value) {
  if (!value) return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

export function formatClock(value = new Date(), timeZone = 'UTC') {
  return value.toLocaleTimeString('en-GB', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
    timeZone,
  });
}

/**
 * Length of the payload sample used by utils.extract_dns_features(): the
 * subdomain when present, otherwise the full name, with separators and other
 * non-alphanumerics removed. Kept in one place so the visual entropy ceiling
 * agrees with the stored entropy_ratio.
 */
export function payloadSampleLength(domain) {
  const clean = String(domain || '').replace(/^\.+|\.+$/g, '').toLowerCase();
  const labels = clean ? clean.split('.') : [];
  const target = labels.length > 2 ? labels.slice(0, -2).join('.') : clean;
  return target.replace(/[^a-z0-9]/g, '').length;
}

export function formatDateTime(value) {
  const date = toDate(value);
  if (!date) return '—';
  return date.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
    timeZone: 'UTC',
  });
}

export function formatDate(value) {
  const date = toDate(value);
  if (!date) return '—';
  return date.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    timeZone: 'UTC',
  });
}

export function timeAgo(value, now = Date.now()) {
  const date = toDate(value);
  if (!date) return '—';

  const delta = now - date.getTime();
  const future = delta < 0;
  const seconds = Math.max(1, Math.round(Math.abs(delta) / 1000));

  let amount;
  if (seconds < 60) amount = `${seconds}s`;
  else if (seconds < 3600) amount = `${Math.floor(seconds / 60)}m`;
  else if (seconds < 86400) amount = `${Math.floor(seconds / 3600)}h`;
  else if (seconds < 86400 * 30) amount = `${Math.floor(seconds / 86400)}d`;
  else if (seconds < 86400 * 365) amount = `${Math.floor(seconds / (86400 * 30))}mo`;
  else amount = `${Math.floor(seconds / (86400 * 365))}y`;

  return future ? `in ${amount}` : `${amount} ago`;
}

export function formatDuration(milliseconds) {
  const seconds = Math.max(0, Math.floor(milliseconds / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  const mins = minutes % 60;
  if (hours < 24) return mins ? `${hours}h ${mins}m` : `${hours}h`;
  const days = Math.floor(hours / 24);
  const remHours = hours % 24;
  return remHours ? `${days}d ${remHours}h` : `${days}d`;
}

export function formatBytes(bytes) {
  if (!bytes || bytes <= 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

/**
 * Triage deadline by severity. These are policy values, not detector output:
 * Critical 1h, High 4h, Medium 24h, Low 72h.
 */
export const SLA_HOURS = {
  CRITICAL: 1,
  HIGH: 4,
  MEDIUM: 24,
  LOW: 72,
};

const SLA_TERMINAL_STATUSES = ['RESOLVED', 'FALSE POSITIVE', 'CLOSED'];

export function slaFor(severity, createdAt, now = Date.now(), status = null) {
  const created = toDate(createdAt);
  const level = severityOf(severity);
  const hours = SLA_HOURS[level];
  const closed = Boolean(
    status && SLA_TERMINAL_STATUSES.includes(String(status).toUpperCase()),
  );

  if (!created) {
    return {
      level,
      hours,
      dueAt: null,
      state: closed ? 'closed' : 'unknown',
      label: closed ? 'Closed out' : 'No timestamp',
    };
  }

  const total = hours * 60 * 60 * 1000;
  const dueAt = created.getTime() + total;

  if (closed) {
    return {
      level,
      hours,
      dueAt: new Date(dueAt),
      state: 'closed',
      label: 'Closed out',
    };
  }

  const remaining = dueAt - now;

  if (remaining <= 0) {
    return {
      level,
      hours,
      dueAt: new Date(dueAt),
      state: 'overdue',
      label: `Overdue ${formatDuration(-remaining)}`,
    };
  }

  const dueSoonThreshold = Math.min(total * 0.25, 30 * 60 * 1000);
  return {
    level,
    hours,
    dueAt: new Date(dueAt),
    state: remaining <= dueSoonThreshold ? 'due-soon' : 'on-track',
    label: `Due in ${formatDuration(remaining)}`,
  };
}

export function ipContext(value) {
  const ip = String(value || '').trim();
  if (!ip) {
    return { scope: 'unknown', label: 'Unknown source', subnet: '—', isPrivate: false };
  }

  if (ip === '::1' || ip.startsWith('127.')) {
    return { scope: 'loopback', label: 'Loopback', subnet: 'localhost', isPrivate: true };
  }
  if (ip.startsWith('169.254.')) {
    return { scope: 'link-local', label: 'Link-local', subnet: ip.split('.').slice(0, 3).join('.'), isPrivate: true };
  }
  if (ip.includes(':')) {
    return { scope: 'ipv6', label: 'IPv6 address', subnet: 'IPv6', isPrivate: false };
  }

  const octets = ip.split('.').map((part) => Number(part));
  const valid = octets.length === 4 && octets.every((part) => Number.isInteger(part) && part >= 0 && part <= 255);
  if (!valid) {
    return { scope: 'unknown', label: 'Unrecognised address', subnet: '—', isPrivate: false };
  }

  const [a, b] = octets;
  const isPrivate = a === 10
    || (a === 172 && b >= 16 && b <= 31)
    || (a === 192 && b === 168);
  const subnet = `${octets.slice(0, 3).join('.')}.0/24`;

  return {
    scope: isPrivate ? 'private' : 'public',
    label: isPrivate ? 'Internal address' : 'External address',
    subnet,
    isPrivate,
  };
}

export function initials(name) {
  const cleaned = String(name || '').replace(/[()]/g, ' ').trim();
  if (!cleaned || cleaned.toLowerCase() === 'unassigned') return '—';
  return cleaned
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0].toUpperCase())
    .join('');
}
