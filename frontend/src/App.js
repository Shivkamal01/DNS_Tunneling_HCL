import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import './App.css';

import { api, FALLBACK_DEMO_ALERTS, describeError } from './services/api';
import { Header } from './components/Header';
import { MetricsOverview } from './components/MetricsOverview';
import { ThreatAnalytics } from './components/ThreatAnalytics';
import { AlertsTable } from './components/AlertsTable';
import { ForensicDrawer } from './components/ForensicDrawer';
import { TrafficSimulatorModal } from './components/TrafficSimulatorModal';
import { TelemetryStreamModal } from './components/TelemetryStreamModal';
import { IncidentsView } from './components/IncidentsView';
import { WhitelistView } from './components/WhitelistView';
import { ToastContainer } from './components/Toast';

const REFRESH_INTERVAL = 30;
const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

const VIEWS = [
  { key: 'alerts', label: 'Alerts' },
  { key: 'incidents', label: 'Incidents' },
  { key: 'whitelist', label: 'Whitelist' },
];

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
        <div className="error-fallback-screen">
          <div className="error-box">
            <h2>Dashboard error</h2>
            <p>{this.state.error?.message || 'An unexpected rendering error occurred.'}</p>
            <button className="btn-action primary" onClick={() => window.location.reload()}>
              Reload
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

/**
 * Coerce a numeric API field to a number, preserving a genuine 0.
 *
 * The old code used `parseInt(x, 10) || fallback`, which silently replaced a
 * real zero critical-alert count with a client-side recount — and the two
 * counts disagreed whenever the table was paginated.
 */
function toNumber(value, fallback = 0) {
  const parsed = typeof value === 'number' ? value : parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function SOCDashboard() {
  const [alerts, setAlerts] = useState([]);
  const [metricsData, setMetricsData] = useState(null);
  const [incidentSummary, setIncidentSummary] = useState({ total: 0, active: 0 });
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState('connecting');
  const [lastUpdated, setLastUpdated] = useState(null);
  const [countdown, setCountdown] = useState(REFRESH_INTERVAL);
  const [activeView, setActiveView] = useState('alerts');

  // Filters
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [filterStatus, setFilterStatus] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [sortConfig, setSortConfig] = useState({ key: 'created_at', dir: 'desc' });
  const [density, setDensity] = useState('normal');

  // Overlays
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [isSimulatorOpen, setIsSimulatorOpen] = useState(false);
  const [isTelemetryOpen, setIsTelemetryOpen] = useState(false);
  const [toasts, setToasts] = useState([]);

  const toastIdRef = useRef(0);
  const alertsRef = useRef(alerts);
  useEffect(() => { alertsRef.current = alerts; }, [alerts]);

  /* ─── Toasts ──────────────────────────────────────────────────────────── */
  const addToast = useCallback((message, type = 'info', title = null) => {
    const id = ++toastIdRef.current;
    setToasts((prev) => [...prev, { id, message, type, title, exiting: false }]);
    setTimeout(() => {
      setToasts((prev) => prev.map((t) => (t.id === id ? { ...t, exiting: true } : t)));
      setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), 300);
    }, 4200);
  }, []);

  const dismissToast = useCallback((id) => {
    setToasts((prev) => prev.map((t) => (t.id === id ? { ...t, exiting: true } : t)));
    setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), 300);
  }, []);

  /* ─── Data loading ────────────────────────────────────────────────────── */
  const fetchAllData = useCallback(async (quiet = false) => {
    if (!quiet) setIsLoading(true);
    else setIsRefreshing(true);

    const [alertsRes, metricsRes, incidentsRes] = await Promise.allSettled([
      api.getAlerts({ limit: 200 }),
      api.getMetrics(),
      api.getIncidents(),
    ]);

    let isLive = false;

    if (alertsRes.status === 'fulfilled' && alertsRes.value?.data) {
      setAlerts(alertsRes.value.data);
      isLive = true;
    }

    if (metricsRes.status === 'fulfilled' && metricsRes.value?.data) {
      setMetricsData(metricsRes.value.data);
    }

    if (incidentsRes.status === 'fulfilled' && incidentsRes.value?.data) {
      const list = incidentsRes.value.data;
      setIncidentSummary({
        total: list.length,
        active: list.filter((i) => ['OPEN', 'INVESTIGATING'].includes((i.status || '').toUpperCase())).length,
      });
    }

    if (isLive) {
      setConnectionStatus('online');
      setLastUpdated(new Date());
    } else {
      // Backend unreachable: show the sample set once so the layout is still
      // demonstrable, and label the connection state honestly.
      if (alertsRef.current.length === 0) setAlerts(FALLBACK_DEMO_ALERTS);
      setConnectionStatus('offline');
    }

    setIsLoading(false);
    setIsRefreshing(false);
    setCountdown(REFRESH_INTERVAL);
  }, []);

  useEffect(() => { fetchAllData(); }, [fetchAllData]);

  /* ─── Auto-refresh ────────────────────────────────────────────────────── */
  useEffect(() => {
    const timer = setInterval(() => {
      setCountdown((current) => {
        if (current <= 1) {
          fetchAllData(true);
          return REFRESH_INTERVAL;
        }
        return current - 1;
      });
    }, 1000);
    return () => clearInterval(timer);
  }, [fetchAllData]);

  /* ─── Status change (optimistic, with rollback) ───────────────────────── */
  const handleStatusChange = async (alertId, newStatus, domain = '') => {
    const previous = alerts.find((a) => a.id === alertId)?.status;

    setAlerts((prev) => prev.map((a) => (a.id === alertId ? { ...a, status: newStatus } : a)));
    if (selectedAlert?.id === alertId) {
      setSelectedAlert((prev) => (prev ? { ...prev, status: newStatus } : prev));
    }

    try {
      await api.updateAlertStatus(alertId, newStatus);
      addToast(`${domain || `Alert #${alertId}`}: ${previous} → ${newStatus}`, 'success', 'Status updated');
    } catch (error) {
      setAlerts((prev) => prev.map((a) => (a.id === alertId ? { ...a, status: previous } : a)));
      if (selectedAlert?.id === alertId) {
        setSelectedAlert((prev) => (prev ? { ...prev, status: previous } : prev));
      }
      addToast(describeError(error), 'error', 'Update failed');
    }
  };

  const handleUpdateStatusAndNotes = async (alertId, status, notes) => {
    try {
      await api.updateAlertStatus(alertId, status, notes);
      setAlerts((prev) => prev.map((a) => (a.id === alertId ? { ...a, status, analyst_notes: notes } : a)));
      if (selectedAlert?.id === alertId) {
        setSelectedAlert((prev) => (prev ? { ...prev, status, analyst_notes: notes } : prev));
      }
      addToast(`Triage record saved for alert #${alertId}`, 'success', 'Saved');
    } catch (error) {
      addToast(describeError(error), 'error', 'Save failed');
    }
  };

  /* ─── Sorting ─────────────────────────────────────────────────────────── */
  const handleSort = (key) => {
    setSortConfig((prev) => ({
      key,
      dir: prev.key === key && prev.dir === 'desc' ? 'asc' : 'desc',
    }));
  };

  /* ─── Derived alert set ───────────────────────────────────────────────── */
  const searchLower = searchQuery.toLowerCase().trim();

  const filteredAlerts = useMemo(() => {
    return alerts
      .filter((a) => filterSeverity === 'ALL' || (a.severity || '').toUpperCase() === filterSeverity)
      .filter((a) => filterStatus === 'ALL' || (a.status || '').toUpperCase() === filterStatus)
      .filter((a) => {
        if (!searchLower) return true;
        return (
          (a.domain || '').toLowerCase().includes(searchLower) ||
          (a.source_ip || '').toLowerCase().includes(searchLower) ||
          (a.detection_reason || '').toLowerCase().includes(searchLower) ||
          (a.indicators || '').toLowerCase().includes(searchLower) ||
          (a.severity || '').toLowerCase().includes(searchLower)
        );
      })
      .sort((a, b) => {
        let av = a[sortConfig.key];
        let bv = b[sortConfig.key];

        if (sortConfig.key === 'severity') {
          av = SEVERITY_ORDER.indexOf((av || 'LOW').toUpperCase());
          bv = SEVERITY_ORDER.indexOf((bv || 'LOW').toUpperCase());
        } else if (sortConfig.key === 'created_at') {
          av = new Date(av || 0).getTime();
          bv = new Date(bv || 0).getTime();
        } else if (typeof av === 'string') {
          av = av.toLowerCase();
          bv = (bv || '').toLowerCase();
        }

        if (av < bv) return sortConfig.dir === 'desc' ? 1 : -1;
        if (av > bv) return sortConfig.dir === 'desc' ? -1 : 1;
        return 0;
      });
  }, [alerts, filterSeverity, filterStatus, searchLower, sortConfig]);

  /* ─── Header metrics ──────────────────────────────────────────────────── */
  const stats = useMemo(() => {
    const overview = metricsData?.overview;
    const countBy = (predicate) => alerts.filter(predicate).length;

    return {
      total: toNumber(overview?.total_alerts, alerts.length),
      critical: toNumber(overview?.critical_alerts, countBy((a) => (a.severity || '').toUpperCase() === 'CRITICAL')),
      open: toNumber(overview?.open_alerts, countBy((a) => (a.status || '').toUpperCase() === 'OPEN')),
      resolved: toNumber(
        overview?.resolved_alerts,
        countBy((a) => ['RESOLVED', 'FALSE POSITIVE'].includes((a.status || '').toUpperCase())),
      ),
      suppressed: toNumber(overview?.suppressed_queries, 0),
      incidents: incidentSummary.total,
      activeIncidents: incidentSummary.active,
    };
  }, [alerts, metricsData, incidentSummary]);

  const avgRisk = useMemo(() => {
    if (metricsData?.overview?.avg_risk_score !== undefined) {
      return toNumber(metricsData.overview.avg_risk_score);
    }
    if (alerts.length === 0) return 0;
    return Math.round(alerts.reduce((sum, a) => sum + (a.risk_score || 0), 0) / alerts.length);
  }, [alerts, metricsData]);

  const totalExfilBytes = useMemo(() => {
    if (metricsData?.overview?.total_payload_bytes !== undefined) {
      return toNumber(metricsData.overview.total_payload_bytes);
    }
    return alerts.reduce((sum, a) => sum + (a.est_payload_bytes || 0), 0);
  }, [alerts, metricsData]);

  /* ─── Actions ─────────────────────────────────────────────────────────── */
  const handleCopyText = (text, message = 'Copied to clipboard') => {
    if (navigator.clipboard?.writeText) {
      navigator.clipboard.writeText(text).catch(() => {});
    }
    addToast(message, 'info');
  };

  const handleSimulate = async (scenario, count) => {
    try {
      const payload = await api.simulateTraffic(scenario, count);
      addToast(payload.message, 'success', 'Traffic injected');
      fetchAllData(true);
      return payload;
    } catch (error) {
      throw new Error(describeError(error));
    }
  };

  const handleIngestZeek = async () => {
    try {
      const payload = await api.triggerZeekIngest();
      addToast(
        `${payload.inserted} queries added, ${payload.skipped} duplicates skipped, ${payload.alerts} alerts`,
        'success',
        'Zeek ingestion',
      );
      fetchAllData(true);
      return payload;
    } catch (error) {
      throw new Error(describeError(error));
    }
  };

  const handleIngestPcap = async () => {
    try {
      const payload = await api.triggerPcapIngest();
      addToast(
        `${payload.inserted} queries added, ${payload.skipped} duplicates skipped, ${payload.alerts} alerts`,
        'success',
        'PCAP analysis',
      );
      fetchAllData(true);
      return payload;
    } catch (error) {
      throw new Error(describeError(error));
    }
  };

  const handleExport = (format) => {
    window.open(api.getExportUrl(format), '_blank');
    addToast(`Preparing ${format.toUpperCase()} export`, 'info');
  };

  const toggleDensity = () => setDensity((d) => (d === 'normal' ? 'compact' : 'normal'));

  return (
    <div className="soc-app">
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />

      <Header
        connectionStatus={connectionStatus}
        lastUpdated={lastUpdated}
        countdown={countdown}
        refreshInterval={REFRESH_INTERVAL}
        isRefreshing={isRefreshing}
        onRefresh={() => fetchAllData(true)}
        onOpenSimulator={() => setIsSimulatorOpen(true)}
        onOpenTelemetry={() => setIsTelemetryOpen(true)}
        onExport={handleExport}
        density={density}
        onToggleDensity={toggleDensity}
      />

      <nav className="view-tabs" role="tablist" aria-label="Dashboard sections">
        {VIEWS.map((view) => (
          <button
            key={view.key}
            role="tab"
            aria-selected={activeView === view.key}
            className={`view-tab ${activeView === view.key ? 'active' : ''}`}
            onClick={() => setActiveView(view.key)}
          >
            {view.label}
            {view.key === 'alerts' && <span className="view-tab-count">{stats.total}</span>}
            {view.key === 'incidents' && <span className="view-tab-count">{stats.incidents}</span>}
            {view.key === 'whitelist' && <span className="view-tab-count">{stats.suppressed}</span>}
          </button>
        ))}
      </nav>

      <main className="soc-main">
        {activeView === 'alerts' && (
          <>
            <MetricsOverview
              stats={stats}
              avgRisk={avgRisk}
              totalExfilBytes={totalExfilBytes}
            />

            <ThreatAnalytics
              alerts={alerts}
              metricsData={metricsData}
              isLoading={isLoading}
            />

            <AlertsTable
              alerts={alerts}
              filteredAlerts={filteredAlerts}
              filterSeverity={filterSeverity}
              setFilterSeverity={setFilterSeverity}
              filterStatus={filterStatus}
              setFilterStatus={setFilterStatus}
              searchQuery={searchQuery}
              setSearchQuery={setSearchQuery}
              sortConfig={sortConfig}
              onSort={handleSort}
              onStatusChange={handleStatusChange}
              onSelectAlert={setSelectedAlert}
              selectedAlertId={selectedAlert?.id}
              density={density}
              isLoading={isLoading}
            />
          </>
        )}

        {activeView === 'incidents' && (
          <IncidentsView onNotify={addToast} onChanged={() => fetchAllData(true)} />
        )}

        {activeView === 'whitelist' && (
          <WhitelistView onNotify={addToast} onChanged={() => fetchAllData(true)} />
        )}
      </main>

      <ForensicDrawer
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
        onUpdateStatus={handleUpdateStatusAndNotes}
        onCopyText={handleCopyText}
      />

      <TrafficSimulatorModal
        isOpen={isSimulatorOpen}
        onClose={() => setIsSimulatorOpen(false)}
        onSimulate={handleSimulate}
        onIngestZeek={handleIngestZeek}
        onIngestPcap={handleIngestPcap}
      />

      <TelemetryStreamModal
        isOpen={isTelemetryOpen}
        onClose={() => setIsTelemetryOpen(false)}
      />

      <footer className="soc-footer">
        <div className="footer-left">
          <span>HCL · DNS Tunneling Detection</span>
          <span className="footer-sep">/</span>
          <span>{stats.total} alerts · {stats.activeIncidents} active incidents</span>
        </div>
        <div className="footer-right">
          <span>Refresh in <strong>{countdown}s</strong></span>
          <span className="footer-sep">/</span>
          <span><kbd>Ctrl</kbd>+<kbd>K</kbd> search</span>
          <span className="footer-sep">/</span>
          <span><kbd>Esc</kbd> close</span>
        </div>
      </footer>
    </div>
  );
}

export default function App() {
  return (
    <ErrorBoundary>
      <SOCDashboard />
    </ErrorBoundary>
  );
}
