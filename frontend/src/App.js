import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import axios from 'axios';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid,
  ResponsiveContainer, Cell, PieChart, Pie, Legend, AreaChart, Area
} from 'recharts';
import './App.css';

/* ─── API Base URL ────────────────────────────────────────────────────────── */
const API_BASE = process.env.REACT_APP_API_URL || 'http://127.0.0.1:8000';

/* ─── Fallback demo data (used when backend is offline) ─────────────────── */
const DEMO_ALERTS = [
  { id: 1, domain: 'xfiltrate-c2.net',       source_ip: '192.168.1.45',  severity: 'CRITICAL', risk_score: 98, detection_reason: 'High-volume TXT record exfiltration',         status: 'OPEN',          created_at: new Date().toISOString() },
  { id: 2, domain: 'malicious-update.xyz',    source_ip: '10.0.0.12',     severity: 'CRITICAL', risk_score: 94, detection_reason: 'Base64-encoded payloads in subdomain labels', status: 'OPEN',          created_at: new Date().toISOString() },
  { id: 3, domain: 'cdn-delivery-api.com',    source_ip: '172.16.3.21',   severity: 'HIGH',     risk_score: 82, detection_reason: 'Unusually long subdomain names (>52 chars)',  status: 'INVESTIGATING', created_at: new Date().toISOString() },
  { id: 4, domain: 'telemetry-metrics.io',    source_ip: '10.10.5.87',    severity: 'HIGH',     risk_score: 76, detection_reason: 'Rapid successive CNAME lookups',              status: 'OPEN',          created_at: new Date().toISOString() },
  { id: 5, domain: 'beacon-track.biz',        source_ip: '192.168.2.100', severity: 'MEDIUM',   risk_score: 63, detection_reason: 'Abnormal query frequency pattern',            status: 'OPEN',          created_at: new Date().toISOString() },
  { id: 6, domain: 'update-server-check.org', source_ip: '10.0.0.9',      severity: 'MEDIUM',   risk_score: 55, detection_reason: 'Repeated NULL/ANY record queries',           status: 'CONTAINED',     created_at: new Date().toISOString() },
  { id: 7, domain: 'cdn-staticfiles.net',     source_ip: '192.168.5.13',  severity: 'LOW',      risk_score: 38, detection_reason: 'Periodic low-rate beaconing',                status: 'RESOLVED',      created_at: new Date().toISOString() },
  { id: 8, domain: 'fonts.trusted-cdn.io',    source_ip: '10.0.1.3',      severity: 'LOW',      risk_score: 22, detection_reason: 'Unusual PTR record queries',                 status: 'FALSE POSITIVE', created_at: new Date().toISOString() },
];

/* ─── Helpers ────────────────────────────────────────────────────────────── */
const getRiskColor = (score) => {
  if (score >= 90) return '#ef4444';
  if (score >= 70) return '#f97316';
  if (score >= 50) return '#38bdf8';
  return '#10b981';
};

const getRiskLabel = (score) => {
  if (score >= 90) return 'Critical';
  if (score >= 70) return 'High';
  if (score >= 50) return 'Medium';
  return 'Low';
};

const formatTimestamp = (ts) => {
  if (!ts) return '—';
  try {
    const date = new Date(ts);
    if (isNaN(date.getTime())) return '—';
    return date.toLocaleString('en-US', {
      month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit',
      hour12: true
    });
  } catch {
    return '—';
  }
};

const timeAgo = (ts) => {
  if (!ts) return '';
  try {
    const diff = Date.now() - new Date(ts).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return 'just now';
    if (mins < 60) return `${mins}m ago`;
    const hours = Math.floor(mins / 60);
    if (hours < 24) return `${hours}h ago`;
    return `${Math.floor(hours / 24)}d ago`;
  } catch {
    return '';
  }
};

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const PIE_COLORS = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#38bdf8', LOW: '#10b981' };
const STATUS_COLORS = {
  'OPEN':           { bg: 'rgba(239,68,68,0.12)',   text: '#fca5a5', border: 'rgba(239,68,68,0.35)' },
  'INVESTIGATING':  { bg: 'rgba(249,115,22,0.12)',  text: '#fdba74', border: 'rgba(249,115,22,0.35)' },
  'CONTAINED':      { bg: 'rgba(56,189,248,0.12)',  text: '#7dd3fc', border: 'rgba(56,189,248,0.35)' },
  'RESOLVED':       { bg: 'rgba(16,185,129,0.12)',  text: '#6ee7b7', border: 'rgba(16,185,129,0.35)' },
  'FALSE POSITIVE': { bg: 'rgba(148,163,184,0.12)', text: '#94a3b8', border: 'rgba(148,163,184,0.35)' },
};

const REFRESH_INTERVAL = 30; // seconds

/* ─── Animated Counter Hook ──────────────────────────────────────────────── */
function useAnimatedCounter(target, duration = 600) {
  const [display, setDisplay] = useState(0);
  const rafRef = useRef(null);
  const prevTarget = useRef(target);

  useEffect(() => {
    const start = prevTarget.current !== target ? display : 0;
    prevTarget.current = target;
    const diff = target - start;
    if (diff === 0) return;
    const startTime = performance.now();

    const step = (now) => {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setDisplay(Math.round(start + diff * eased));
      if (progress < 1) rafRef.current = requestAnimationFrame(step);
    };

    rafRef.current = requestAnimationFrame(step);
    return () => { if (rafRef.current) cancelAnimationFrame(rafRef.current); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [target, duration]);

  return display;
}

/* ─── Sub-components ─────────────────────────────────────────────────────── */
function StatCard({ label, value, icon, color, subtitle, trend }) {
  const animatedValue = useAnimatedCounter(value);
  return (
    <div className="stat-card" style={{ '--accent-color': color }}>
      <div className="stat-icon">{icon}</div>
      <div className="stat-body">
        <div className="stat-value-row">
          <div className="stat-value">{animatedValue}</div>
          {trend && <span className={`stat-trend ${trend > 0 ? 'up' : 'down'}`}>{trend > 0 ? '↑' : '↓'}</span>}
        </div>
        <div className="stat-label">{label}</div>
        {subtitle && <div className="stat-subtitle">{subtitle}</div>}
      </div>
    </div>
  );
}

function CustomPieLabel({ cx, cy, midAngle, innerRadius, outerRadius, percent }) {
  if (percent < 0.06) return null;
  const RADIAN = Math.PI / 180;
  const radius = innerRadius + (outerRadius - innerRadius) * 0.55;
  const x = cx + radius * Math.cos(-midAngle * RADIAN);
  const y = cy + radius * Math.sin(-midAngle * RADIAN);
  return (
    <text x={x} y={y} fill="white" textAnchor="middle" dominantBaseline="central" fontSize={12} fontWeight={600}>
      {`${(percent * 100).toFixed(0)}%`}
    </text>
  );
}

function StatusBadge({ status }) {
  const s = STATUS_COLORS[status] || STATUS_COLORS['OPEN'];
  return (
    <span className="status-badge" style={{ background: s.bg, color: s.text, border: `1px solid ${s.border}` }}>
      <span className={`status-dot ${status === 'OPEN' ? 'pulse' : ''}`} style={{ background: s.text }} />
      {status}
    </span>
  );
}

/* ─── Toast Notification ─────────────────────────────────────────────────── */
function ToastContainer({ toasts, onDismiss }) {
  return (
    <div className="toast-container" role="alert" aria-live="polite">
      {toasts.map(t => (
        <div
          key={t.id}
          className={`toast toast-${t.type} ${t.exiting ? 'toast-exit' : 'toast-enter'}`}
        >
          <span className="toast-icon">
            {t.type === 'success' ? '✓' : t.type === 'error' ? '✕' : 'ℹ'}
          </span>
          <span className="toast-msg">{t.message}</span>
          <button className="toast-close" onClick={() => onDismiss(t.id)} aria-label="Dismiss notification">×</button>
        </div>
      ))}
    </div>
  );
}

/* ─── Search Bar ─────────────────────────────────────────────────────────── */
function SearchBar({ value, onChange }) {
  const inputRef = useRef(null);

  useEffect(() => {
    const handler = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        inputRef.current?.focus();
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  return (
    <div className="search-bar-wrapper">
      <svg className="search-icon-svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <circle cx="11" cy="11" r="8" />
        <line x1="21" y1="21" x2="16.65" y2="16.65" />
      </svg>
      <input
        ref={inputRef}
        type="text"
        className="search-input"
        placeholder="Search domains, IPs, reasons…"
        value={value}
        onChange={e => onChange(e.target.value)}
        aria-label="Search alerts"
      />
      {value && (
        <button className="search-clear" onClick={() => onChange('')} aria-label="Clear search">×</button>
      )}
      <kbd className="search-kbd">Ctrl+K</kbd>
    </div>
  );
}

/* ─── Risk Score Gauge (mini) ────────────────────────────────────────────── */
function RiskGauge({ score }) {
  const color = getRiskColor(score);
  const circumference = 2 * Math.PI * 18;
  const offset = circumference - (score / 100) * circumference;

  return (
    <div className="risk-gauge" title={`${getRiskLabel(score)} Risk: ${score}/100`}>
      <svg width="48" height="48" viewBox="0 0 48 48" aria-hidden="true">
        <circle cx="24" cy="24" r="18" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="4" />
        <circle
          cx="24" cy="24" r="18"
          fill="none"
          stroke={color}
          strokeWidth="4"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          transform="rotate(-90 24 24)"
          className="risk-gauge-arc"
        />
      </svg>
      <span className="risk-gauge-value" style={{ color }}>{score}</span>
    </div>
  );
}

/* ─── Custom Bar Tooltip ─────────────────────────────────────────────────── */
function CustomBarTooltip({ active, payload }) {
  if (!active || !payload?.length) return null;
  const d = payload[0].payload;
  return (
    <div className="custom-tooltip">
      <div className="tooltip-domain">{d.domain}</div>
      <div className="tooltip-row">
        <span className="tooltip-label">Risk Score</span>
        <span className="tooltip-val" style={{ color: getRiskColor(d.risk_score) }}>{d.risk_score}/100</span>
      </div>
      <div className="tooltip-row">
        <span className="tooltip-label">Severity</span>
        <span className={`tooltip-sev ${d.severity?.toLowerCase()}`}>{d.severity}</span>
      </div>
      <div className="tooltip-row">
        <span className="tooltip-label">Source IP</span>
        <span className="tooltip-val mono">{d.source_ip}</span>
      </div>
    </div>
  );
}

/* ─── Custom Area Tooltip ────────────────────────────────────────────────── */
function CustomAreaTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="custom-tooltip">
      <div className="tooltip-domain">{label}</div>
      <div className="tooltip-row">
        <span className="tooltip-label">Alerts</span>
        <span className="tooltip-val">{payload[0].value}</span>
      </div>
    </div>
  );
}

/* ─── Highlight search matches ───────────────────────────────────────────── */
function highlightMatch(text, query) {
  if (!query || !text) return text || '';
  const escaped = query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const parts = String(text).split(new RegExp(`(${escaped})`, 'gi'));
  return parts.map((part, i) =>
    part.toLowerCase() === query.toLowerCase()
      ? <mark key={i} className="search-highlight">{part}</mark>
      : part
  );
}

/* ─── Error Boundary ─────────────────────────────────────────────────────── */
class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="error-boundary">
          <div className="error-boundary-content">
            <span className="error-boundary-icon">⚠️</span>
            <h2>Something went wrong</h2>
            <p>{this.state.error?.message || 'An unexpected error occurred in the dashboard.'}</p>
            <button className="btn-refresh" onClick={() => window.location.reload()}>
              Reload Dashboard
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

/* ─── Main Component ─────────────────────────────────────────────────────── */
function App() {
  const [alerts, setAlerts]           = useState([]);
  const [isLoading, setIsLoading]     = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [filterStatus, setFilterStatus]     = useState('ALL');
  const [expandedRow, setExpandedRow]       = useState(null);
  const [countdown, setCountdown]           = useState(REFRESH_INTERVAL);
  const [sortConfig, setSortConfig]         = useState({ key: 'risk_score', dir: 'desc' });
  const [searchQuery, setSearchQuery]       = useState('');
  const [toasts, setToasts]                 = useState([]);
  const [connectionStatus, setConnectionStatus] = useState('connecting');
  const [lastUpdated, setLastUpdated]       = useState(null);
  const toastIdRef = useRef(0);
  const alertsRef = useRef(alerts);

  // Keep alertsRef in sync so fetchAlerts never has a stale closure
  useEffect(() => { alertsRef.current = alerts; }, [alerts]);

  /* ── Toast helpers ── */
  const addToast = useCallback((message, type = 'success') => {
    const id = ++toastIdRef.current;
    setToasts(prev => [...prev, { id, message, type, exiting: false }]);
    setTimeout(() => {
      setToasts(prev => prev.map(t => t.id === id ? { ...t, exiting: true } : t));
      setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 350);
    }, 3500);
  }, []);

  const dismissToast = useCallback((id) => {
    setToasts(prev => prev.map(t => t.id === id ? { ...t, exiting: true } : t));
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 350);
  }, []);

  /* ── Fetch ── */
  const fetchAlerts = useCallback((quiet = false) => {
    if (!quiet) setIsLoading(true);
    else setIsRefreshing(true);

    axios.get(`${API_BASE}/api/alerts`, { timeout: 8000 })
      .then(res => {
        if (res.data.status === 'success') {
          setAlerts(res.data.data || []);
          setConnectionStatus('online');
          setLastUpdated(new Date());
        }
      })
      .catch(() => {
        // Use ref to avoid stale closure
        if (alertsRef.current.length === 0) setAlerts(DEMO_ALERTS);
        setConnectionStatus('offline');
      })
      .finally(() => {
        setIsLoading(false);
        setIsRefreshing(false);
        setCountdown(REFRESH_INTERVAL);
      });
  }, []);

  useEffect(() => { fetchAlerts(); }, [fetchAlerts]);

  /* ── Auto-refresh countdown ── */
  useEffect(() => {
    const tick = setInterval(() => {
      setCountdown(c => {
        if (c <= 1) { fetchAlerts(true); return REFRESH_INTERVAL; }
        return c - 1;
      });
    }, 1000);
    return () => clearInterval(tick);
  }, [fetchAlerts]);

  /* ── Keyboard shortcuts ── */
  useEffect(() => {
    const handler = (e) => {
      if (e.key === 'Escape' && expandedRow !== null) {
        setExpandedRow(null);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [expandedRow]);

  /* ── Status update ── */
  const handleStatusChange = (alertId, newStatus, domain) => {
    const prevAlert = alerts.find(a => a.id === alertId);
    const prevStatus = prevAlert?.status;

    // Optimistic update
    setAlerts(prev => prev.map(a => a.id === alertId ? { ...a, status: newStatus } : a));

    axios.put(`${API_BASE}/api/alerts/${alertId}/status`, { status: newStatus }, { timeout: 5000 })
      .then(() => {
        addToast(`${domain}: ${prevStatus} → ${newStatus}`, 'success');
      })
      .catch(() => {
        // Revert on failure
        setAlerts(prev => prev.map(a => a.id === alertId ? { ...a, status: prevStatus } : a));
        addToast(`Failed to update status for ${domain}`, 'error');
      });
  };

  /* ── Sort ── */
  const handleSort = (key) => {
    setSortConfig(prev => ({
      key,
      dir: prev.key === key && prev.dir === 'desc' ? 'asc' : 'desc',
    }));
  };

  const SortIcon = ({ col }) => {
    if (sortConfig.key !== col) return <span className="sort-icon neutral">⇅</span>;
    return <span className="sort-icon active">{sortConfig.dir === 'desc' ? '↓' : '↑'}</span>;
  };

  /* ── Derived data (memoized) ── */
  const searchLower = searchQuery.toLowerCase();
  const filtered = useMemo(() => {
    return alerts
      .filter(a => filterSeverity === 'ALL' || a.severity === filterSeverity)
      .filter(a => filterStatus   === 'ALL' || a.status   === filterStatus)
      .filter(a => {
        if (!searchQuery) return true;
        return (
          (a.domain || '').toLowerCase().includes(searchLower) ||
          (a.source_ip || '').toLowerCase().includes(searchLower) ||
          (a.detection_reason || '').toLowerCase().includes(searchLower) ||
          (a.severity || '').toLowerCase().includes(searchLower)
        );
      })
      .sort((a, b) => {
        let av = a[sortConfig.key];
        let bv = b[sortConfig.key];
        if (sortConfig.key === 'severity') {
          av = SEVERITY_ORDER.indexOf(av);
          bv = SEVERITY_ORDER.indexOf(bv);
        }
        if (typeof av === 'string') {
          av = av.toLowerCase();
          bv = (bv || '').toLowerCase();
        }
        if (av < bv) return sortConfig.dir === 'desc' ? 1 : -1;
        if (av > bv) return sortConfig.dir === 'desc' ? -1 : 1;
        return 0;
      });
  }, [alerts, filterSeverity, filterStatus, searchQuery, searchLower, sortConfig]);

  const stats = useMemo(() => ({
    total:    alerts.length,
    critical: alerts.filter(a => a.severity === 'CRITICAL').length,
    open:     alerts.filter(a => a.status === 'OPEN').length,
    resolved: alerts.filter(a => a.status === 'RESOLVED' || a.status === 'FALSE POSITIVE').length,
  }), [alerts]);

  const avgRisk = alerts.length > 0
    ? Math.round(alerts.reduce((sum, a) => sum + (a.risk_score || 0), 0) / alerts.length)
    : 0;

  const pieData = useMemo(() =>
    SEVERITY_ORDER
      .map(sev => ({ name: sev, value: alerts.filter(a => a.severity === sev).length }))
      .filter(d => d.value > 0),
    [alerts]
  );

  // Timeline data — group alerts by severity for the area chart
  const timelineData = useMemo(() => {
    const sorted = [...alerts]
      .filter(a => a.risk_score != null)
      .sort((a, b) => (a.risk_score || 0) - (b.risk_score || 0));
    return sorted.slice(0, 12).map(a => ({
      domain: (a.domain || '').length > 18 ? (a.domain || '').substring(0, 16) + '…' : (a.domain || ''),
      risk_score: a.risk_score || 0,
    }));
  }, [alerts]);

  /* ── Clear all filters ── */
  const hasActiveFilters = filterSeverity !== 'ALL' || filterStatus !== 'ALL' || searchQuery !== '';
  const clearFilters = () => {
    setFilterSeverity('ALL');
    setFilterStatus('ALL');
    setSearchQuery('');
  };

  return (
    <div className="dashboard">
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />

      {/* ── Header ── */}
      <header className="header" role="banner">
        <div className="header-left">
          <div className="logo" aria-hidden="true">
            <svg width="32" height="32" viewBox="0 0 32 32" fill="none">
              <circle cx="16" cy="16" r="15" stroke="#38bdf8" strokeWidth="1.5" />
              <path d="M8 16 Q16 6 24 16 Q16 26 8 16Z" fill="rgba(56,189,248,0.2)" stroke="#38bdf8" strokeWidth="1.2"/>
              <circle cx="16" cy="16" r="3" fill="#38bdf8"/>
            </svg>
          </div>
          <div>
            <h1>SOC Dashboard</h1>
            <p className="header-sub">DNS Tunneling Detection &amp; Threat Intelligence Platform</p>
          </div>
        </div>
        <div className="header-right">
          <div className={`connection-indicator ${connectionStatus}`}>
            <span className="connection-dot" />
            <span className="connection-text">
              {connectionStatus === 'online' ? 'Live' : connectionStatus === 'offline' ? 'Demo Mode' : 'Connecting…'}
            </span>
          </div>
          {lastUpdated && (
            <div className="last-updated" title={lastUpdated.toLocaleString()}>
              Updated {timeAgo(lastUpdated)}
            </div>
          )}
          <div className={`refresh-badge ${isRefreshing ? 'spinning' : ''}`}>
            <span className="refresh-icon" aria-hidden="true">↻</span>
            <span>Refresh in <strong>{countdown}s</strong></span>
            <div className="refresh-progress">
              <div className="refresh-progress-fill" style={{ width: `${((REFRESH_INTERVAL - countdown) / REFRESH_INTERVAL) * 100}%` }} />
            </div>
          </div>
          <button className="btn-refresh" onClick={() => fetchAlerts(true)} disabled={isRefreshing} aria-label="Refresh alerts data">
            {isRefreshing ? 'Refreshing…' : 'Refresh Now'}
          </button>
        </div>
      </header>

      {/* ── Stat Cards ── */}
      <div className="stat-grid" role="region" aria-label="Alert statistics">
        <StatCard label="Total Alerts"    value={stats.total}    icon="🛡️" color="#38bdf8" subtitle={`Avg risk: ${avgRisk}`} />
        <StatCard label="Critical Threats" value={stats.critical} icon="🔴" color="#ef4444" subtitle={stats.critical > 0 ? 'Immediate action needed' : 'All clear'} />
        <StatCard label="Open Incidents"  value={stats.open}     icon="⚠️" color="#f97316" subtitle={stats.open > 0 ? `${Math.round(stats.open / Math.max(stats.total, 1) * 100)}% unresolved` : 'None pending'} />
        <StatCard label="Resolved"        value={stats.resolved} icon="✅" color="#10b981" subtitle={stats.total > 0 ? `${Math.round(stats.resolved / stats.total * 100)}% resolution rate` : 'No data'} />
      </div>

      <div className="content">
        {/* ── Charts Row ── */}
        <div className="charts-row">
          <div className="chart-container chart-bar">
            <h2>Risk Score Distribution</h2>
            {isLoading ? <div className="loading-skeleton" /> : (
              <ResponsiveContainer width="100%" height={280}>
                <BarChart data={alerts.slice(0, 10)} margin={{ top: 10, right: 20, left: -10, bottom: 60 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" vertical={false} />
                  <XAxis
                    dataKey="domain"
                    tick={{ fill: '#64748b', fontSize: 10 }}
                    axisLine={false} tickLine={false}
                    angle={-35} textAnchor="end" interval={0}
                  />
                  <YAxis domain={[0, 100]} tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
                  <Tooltip content={<CustomBarTooltip />} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
                  <Bar dataKey="risk_score" radius={[6, 6, 0, 0]} animationDuration={1200} animationEasing="ease-out">
                    {alerts.slice(0, 10).map((entry, i) => (
                      <Cell key={`bar-${i}`} fill={getRiskColor(entry.risk_score)} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>

          <div className="chart-container chart-pie">
            <h2>Severity Breakdown</h2>
            {isLoading ? <div className="loading-skeleton" /> : (
              <ResponsiveContainer width="100%" height={280}>
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%" cy="45%"
                    innerRadius={68} outerRadius={105}
                    paddingAngle={3}
                    dataKey="value"
                    labelLine={false}
                    label={<CustomPieLabel />}
                    animationDuration={1000}
                    animationEasing="ease-out"
                  >
                    {pieData.map((entry, i) => (
                      <Cell key={`pie-${i}`} fill={PIE_COLORS[entry.name]} />
                    ))}
                  </Pie>
                  <Legend
                    iconType="circle"
                    formatter={(value) => <span style={{ color: '#94a3b8', fontSize: 12 }}>{value}</span>}
                  />
                  <Tooltip
                    contentStyle={{ background: 'rgba(2,6,23,0.95)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 10, color: '#f8fafc' }}
                    formatter={(v, name) => [`${v} alert${v !== 1 ? 's' : ''}`, name]}
                  />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* ── Risk Trend Area Chart ── */}
        {timelineData.length > 2 && (
          <div className="chart-container chart-area">
            <h2>Risk Trend Overview</h2>
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={timelineData} margin={{ top: 10, right: 20, left: -10, bottom: 40 }}>
                <defs>
                  <linearGradient id="riskGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#38bdf8" stopOpacity={0.35} />
                    <stop offset="100%" stopColor="#38bdf8" stopOpacity={0.02} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" vertical={false} />
                <XAxis dataKey="domain" tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} tickLine={false} angle={-25} textAnchor="end" interval={0} />
                <YAxis domain={[0, 100]} tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
                <Tooltip content={<CustomAreaTooltip />} cursor={{ stroke: 'rgba(56,189,248,0.3)', strokeWidth: 1 }} />
                <Area type="monotone" dataKey="risk_score" stroke="#38bdf8" strokeWidth={2} fill="url(#riskGradient)" animationDuration={1500} dot={{ r: 4, fill: '#020617', stroke: '#38bdf8', strokeWidth: 2 }} activeDot={{ r: 6, fill: '#38bdf8' }} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        )}

        {/* ── Table ── */}
        <div className="table-container" role="region" aria-label="Security alerts table">
          <div className="table-header-row">
            <h2>Active Security Alerts</h2>
            <div className="filters">
              <SearchBar value={searchQuery} onChange={setSearchQuery} />
              {/* Severity filter */}
              <div className="filter-tabs" role="tablist" aria-label="Filter by severity">
                {['ALL', ...SEVERITY_ORDER].map(sev => (
                  <button
                    key={sev}
                    className={`filter-tab ${filterSeverity === sev ? 'active' : ''}`}
                    style={filterSeverity === sev && sev !== 'ALL' ? { borderColor: PIE_COLORS[sev], color: PIE_COLORS[sev] } : {}}
                    onClick={() => setFilterSeverity(sev)}
                    role="tab"
                    aria-selected={filterSeverity === sev}
                  >
                    {sev}
                  </button>
                ))}
              </div>
              {/* Status filter */}
              <select className="status-filter-select" value={filterStatus} onChange={e => setFilterStatus(e.target.value)} aria-label="Filter by status">
                <option value="ALL">All Statuses</option>
                <option value="OPEN">Open</option>
                <option value="INVESTIGATING">Investigating</option>
                <option value="CONTAINED">Contained</option>
                <option value="RESOLVED">Resolved</option>
                <option value="FALSE POSITIVE">False Positive</option>
              </select>
              {hasActiveFilters && (
                <button className="btn-clear-filters" onClick={clearFilters}>
                  ✕ Clear Filters
                </button>
              )}
            </div>
          </div>

          {isLoading ? (
            <div className="loading">
              <div className="loading-spinner" />
              <span>Fetching threat intelligence data…</span>
            </div>
          ) : (
            <>
              <div className="result-count">
                {filtered.length} alert{filtered.length !== 1 ? 's' : ''} found
                {hasActiveFilters && <span className="result-filtered"> (filtered from {alerts.length})</span>}
              </div>
              <div className="table-responsive">
                <table>
                  <thead>
                    <tr>
                      <th aria-label="Expand row"></th>
                      <th onClick={() => handleSort('domain')} className="sortable">Domain <SortIcon col="domain"/></th>
                      <th onClick={() => handleSort('source_ip')} className="sortable">Source IP <SortIcon col="source_ip"/></th>
                      <th onClick={() => handleSort('severity')} className="sortable">Severity <SortIcon col="severity"/></th>
                      <th onClick={() => handleSort('risk_score')} className="sortable">Risk Score <SortIcon col="risk_score"/></th>
                      <th>Detection Trigger</th>
                      <th>Time</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.length === 0 && (
                      <tr><td colSpan="8" className="no-results">
                        <div className="no-results-content">
                          <span className="no-results-icon">🔍</span>
                          <p>No alerts match your current filters.</p>
                          {hasActiveFilters && (
                            <button className="btn-clear-filters" onClick={clearFilters}>Clear All Filters</button>
                          )}
                        </div>
                      </td></tr>
                    )}
                    {filtered.map((alert, index) => {
                      const isExpanded = expandedRow === alert.id;
                      return (
                        <React.Fragment key={alert.id}>
                          <tr
                            className={`alert-row ${isExpanded ? 'expanded' : ''} ${(alert.severity || '').toLowerCase()}-row`}
                            onClick={() => setExpandedRow(isExpanded ? null : alert.id)}
                            style={{ animationDelay: `${index * 0.03}s` }}
                          >
                            <td className="expand-cell">
                              <span className={`expand-icon ${isExpanded ? 'open' : ''}`}>▶</span>
                            </td>
                            <td className="domain-cell">
                              {searchQuery ? highlightMatch(alert.domain, searchQuery) : alert.domain}
                            </td>
                            <td className="ip-cell">
                              {searchQuery ? highlightMatch(alert.source_ip, searchQuery) : alert.source_ip}
                            </td>
                            <td>
                              <span className={`severity-badge ${(alert.severity || '').toLowerCase()}`}>
                                {alert.severity}
                              </span>
                            </td>
                            <td>
                              <div className="score-container">
                                <span className="score-number" style={{ color: getRiskColor(alert.risk_score) }}>
                                  {alert.risk_score}
                                </span>
                                <div className="score-track">
                                  <div
                                    className="score-fill"
                                    style={{ width: `${alert.risk_score}%`, background: getRiskColor(alert.risk_score) }}
                                  />
                                </div>
                              </div>
                            </td>
                            <td className="reason-cell">
                              {searchQuery ? highlightMatch(alert.detection_reason, searchQuery) : alert.detection_reason}
                            </td>
                            <td className="time-cell">
                              {formatTimestamp(alert.created_at)}
                            </td>
                            <td onClick={e => e.stopPropagation()}>
                              <select
                                className="status-dropdown"
                                value={alert.status || 'OPEN'}
                                onChange={e => handleStatusChange(alert.id, e.target.value, alert.domain)}
                                aria-label={`Change status for ${alert.domain}`}
                              >
                                <option value="OPEN">Open</option>
                                <option value="INVESTIGATING">Investigating</option>
                                <option value="CONTAINED">Contained</option>
                                <option value="RESOLVED">Resolved</option>
                                <option value="FALSE POSITIVE">False Positive</option>
                              </select>
                            </td>
                          </tr>
                          {isExpanded && (
                            <tr className="detail-row">
                              <td colSpan="8">
                                <div className="detail-panel">
                                  <div className="detail-top-row">
                                    <RiskGauge score={alert.risk_score} />
                                    <div className="detail-top-info">
                                      <div className="detail-domain-big">{alert.domain}</div>
                                      <div className="detail-ip-line">
                                        <span className="detail-label-inline">Source:</span>
                                        <code>{alert.source_ip}</code>
                                        {alert.created_at && (
                                          <>
                                            <span className="detail-separator">·</span>
                                            <span className="detail-label-inline">Detected:</span>
                                            <span className="detail-time">{formatTimestamp(alert.created_at)}</span>
                                          </>
                                        )}
                                      </div>
                                    </div>
                                    <StatusBadge status={alert.status} />
                                  </div>
                                  <div className="detail-grid">
                                    <div className="detail-item">
                                      <span className="detail-label">Alert ID</span>
                                      <span className="detail-value mono">#{String(alert.id).padStart(4, '0')}</span>
                                    </div>
                                    <div className="detail-item">
                                      <span className="detail-label">Full Domain</span>
                                      <span className="detail-value mono">{alert.domain}</span>
                                    </div>
                                    <div className="detail-item">
                                      <span className="detail-label">Source Address</span>
                                      <span className="detail-value mono">{alert.source_ip}</span>
                                    </div>
                                    <div className="detail-item">
                                      <span className="detail-label">Risk Score</span>
                                      <span className="detail-value" style={{ color: getRiskColor(alert.risk_score) }}>
                                        {alert.risk_score} / 100 — {getRiskLabel(alert.risk_score)}
                                      </span>
                                    </div>
                                    <div className="detail-item">
                                      <span className="detail-label">Current Status</span>
                                      <StatusBadge status={alert.status} />
                                    </div>
                                    <div className="detail-item">
                                      <span className="detail-label">Detected At</span>
                                      <span className="detail-value">{formatTimestamp(alert.created_at)}</span>
                                    </div>
                                    <div className="detail-item full-width">
                                      <span className="detail-label">Detection Trigger</span>
                                      <span className="detail-value">{alert.detection_reason}</span>
                                    </div>
                                  </div>
                                  <div className="detail-actions">
                                    <a
                                      className="detail-action-link"
                                      href={`https://www.virustotal.com/gui/domain/${alert.domain}`}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      onClick={e => e.stopPropagation()}
                                    >
                                      🔎 VirusTotal
                                    </a>
                                    <a
                                      className="detail-action-link"
                                      href={`https://www.shodan.io/search?query=${alert.source_ip}`}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      onClick={e => e.stopPropagation()}
                                    >
                                      🌐 Shodan
                                    </a>
                                    <a
                                      className="detail-action-link"
                                      href={`https://www.abuseipdb.com/check/${alert.source_ip}`}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      onClick={e => e.stopPropagation()}
                                    >
                                      🚫 AbuseIPDB
                                    </a>
                                    <button
                                      className="detail-action-btn"
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        navigator.clipboard.writeText(
                                          `Alert #${alert.id} | ${alert.domain} | ${alert.source_ip} | ${alert.severity} | Risk: ${alert.risk_score} | ${alert.detection_reason}`
                                        );
                                        addToast('Alert details copied to clipboard', 'info');
                                      }}
                                    >
                                      📋 Copy Details
                                    </button>
                                  </div>
                                </div>
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
      </div>

      <footer className="footer" role="contentinfo">
        <span>DNS Tunneling Detection Platform · HCL SOC Intelligence</span>
        <span>Data auto-refreshes every {REFRESH_INTERVAL}s · Press <kbd>Esc</kbd> to collapse rows · <kbd>Ctrl+K</kbd> to search</span>
      </footer>
    </div>
  );
}

/* ─── Export with Error Boundary ─────────────────────────────────────────── */
export default function WrappedApp() {
  return (
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  );
}
