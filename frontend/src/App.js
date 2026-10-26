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
import { IncidentDrawer } from './components/IncidentDrawer';
import { WhitelistView } from './components/WhitelistView';
import { ToastContainer } from './components/Toast';

const REFRESH_INTERVAL = 30;
const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

const VIEWS = [
  { key: 'alerts', label: 'Alerts' },
  { key: 'incidents', label: 'Incidents' },
  { key: 'whitelist', label: 'Whitelist' },
];

function viewFromHash() {
  const candidate = window.location.hash.replace(/^#\/?/, '').toLowerCase();
  return VIEWS.some((view) => view.key === candidate) ? candidate : 'alerts';
}

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
  const [alertsTotal, setAlertsTotal] = useState(0);
  const [metricsData, setMetricsData] = useState(null);
  const [incidentSummary, setIncidentSummary] = useState({ total: 0, active: 0 });
  const [incidentRefreshKey, setIncidentRefreshKey] = useState(0);
  const [whitelistCount, setWhitelistCount] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState('connecting');
  const [offlineReason, setOfflineReason] = useState('');
  const [lastUpdated, setLastUpdated] = useState(null);
  const [countdown, setCountdown] = useState(REFRESH_INTERVAL);
  const [activeView, setActiveView] = useState(viewFromHash);

  // Filters
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [filterStatus, setFilterStatus] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [sortConfig, setSortConfig] = useState({ key: 'created_at', dir: 'desc' });
  const [density, setDensity] = useState('normal');

  // Overlays
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [isSimulatorOpen, setIsSimulatorOpen] = useState(false);
  const [isTelemetryOpen, setIsTelemetryOpen] = useState(false);
  const [toasts, setToasts] = useState([]);

  const toastIdRef = useRef(0);
  const detailRequestRef = useRef(0);
  const fetchRequestRef = useRef(0);
  const alertsRef = useRef(alerts);
  useEffect(() => { alertsRef.current = alerts; }, [alerts]);

  /* ─── Toasts ──────────────────────────────────────────────────────────── */
  const addToast = useCallback((message, type = 'info', title = null, duration = null) => {
    const id = ++toastIdRef.current;
    const lifetime = duration ?? (type === 'error' ? 8000 : 4200);
    setToasts((prev) => [...prev, { id, message, type, title, exiting: false }]);
    setTimeout(() => {
      setToasts((prev) => prev.map((t) => (t.id === id ? { ...t, exiting: true } : t)));
      setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), 300);
    }, lifetime);
  }, []);

  const dismissToast = useCallback((id) => {
    setToasts((prev) => prev.map((t) => (t.id === id ? { ...t, exiting: true } : t)));
    setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), 300);
  }, []);

  /* ─── View routing (hash keeps the console linkable) ──────────────────── */
  useEffect(() => {
    const handleLocation = () => setActiveView(viewFromHash());
    window.addEventListener('hashchange', handleLocation);
    window.addEventListener('popstate', handleLocation);
    return () => {
      window.removeEventListener('hashchange', handleLocation);
      window.removeEventListener('popstate', handleLocation);
    };
  }, []);

  useEffect(() => {
    const target = `#/${activeView}`;
    if (window.location.hash !== target) {
      // Canonicalise an empty or unknown hash without creating an extra history
      // entry. Tab clicks push their own entry below, so Back still navigates
      // between views instead of bouncing off the canonicalisation effect.
      window.history.replaceState(null, '', target);
    }
  }, [activeView]);

  /* ─── Data loading ────────────────────────────────────────────────────── */
  const fetchAllData = useCallback(async (quiet = false) => {
    const requestId = ++fetchRequestRef.current;
    if (!quiet) setIsLoading(true);
    else setIsRefreshing(true);

    const [alertsRes, metricsRes, incidentsRes, whitelistRes] = await Promise.allSettled([
      api.getAlerts({ limit: 200 }),
      api.getMetrics(),
      api.getIncidents(),
      api.getWhitelist(),
    ]);

    // Manual refresh, the auto-refresh timer, and post-save refreshes can
    // overlap. Only the newest request may update the console; otherwise an
    // older response can overwrite a just-saved status.
    if (requestId !== fetchRequestRef.current) return;

    let isLive = false;

    if (alertsRes.status === 'fulfilled' && alertsRes.value?.data) {
      setAlerts(alertsRes.value.data);
      setAlertsTotal(toNumber(alertsRes.value.total, alertsRes.value.data.length));
      isLive = true;
      setOfflineReason('');
    } else {
      setOfflineReason(alertsRes.status === 'rejected' ? describeError(alertsRes.reason) : '');
    }

    if (metricsRes.status === 'fulfilled' && metricsRes.value?.data) {
      setMetricsData(metricsRes.value.data);
    }

    if (incidentsRes.status === 'fulfilled' && incidentsRes.value?.data) {
      const list = incidentsRes.value.data;
      const overview = metricsRes.status === 'fulfilled'
        ? metricsRes.value?.data?.overview
        : null;
      setIncidentSummary({
        // Prefer the aggregate count: the queue endpoint is capped, so using
        // its array length here would under-report on a busy console.
        total: toNumber(overview?.total_incidents, list.length),
        active: toNumber(
          overview?.active_incidents,
          list.filter((i) => !['RESOLVED', 'CLOSED', 'FALSE POSITIVE']
            .includes((i.status || 'OPEN').toUpperCase())).length,
        ),
      });
    }

    if (whitelistRes.status === 'fulfilled' && whitelistRes.value?.data) {
      setWhitelistCount(whitelistRes.value.data.length);
    }

    if (isLive) {
      setConnectionStatus('online');
      setLastUpdated(new Date());
    } else if (alertsRes.status === 'rejected') {
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
      if (document.visibilityState === 'hidden') return;
      setCountdown((current) => Math.max(0, current - 1));
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    if (countdown !== 0) return;
    if (document.visibilityState === 'hidden') return;
    fetchAllData(true);
  }, [countdown, fetchAllData]);

  // If the timer reaches zero while the tab is hidden the countdown stays at
  // zero, so the interval above will never fire again on its own. Refresh when
  // the operator returns to the console instead of silently going stale.
  useEffect(() => {
    const handleVisibility = () => {
      if (document.visibilityState === 'visible') fetchAllData(true);
    };
    document.addEventListener('visibilitychange', handleVisibility);
    return () => document.removeEventListener('visibilitychange', handleVisibility);
  }, [fetchAllData]);

  /* ─── Alert detail loading ────────────────────────────────────────────── */
  const openAlert = useCallback(async (alertOrId) => {
    const summary = typeof alertOrId === 'object' && alertOrId !== null
      ? alertOrId
      : { id: alertOrId };

    setSelectedAlert(summary);
    const requestId = ++detailRequestRef.current;

    try {
      const payload = await api.getAlertDetail(summary.id);
      if (detailRequestRef.current === requestId && payload?.data) {
        setSelectedAlert(payload.data);
      }
    } catch (error) {
      if (detailRequestRef.current === requestId) {
        addToast(describeError(error), 'warning', 'Full detail unavailable');
      }
    }
  }, [addToast]);

  const closeAlert = useCallback(() => {
    detailRequestRef.current += 1;
    setSelectedAlert(null);
  }, []);

  /* ─── Status change (optimistic, with rollback) ───────────────────────── */
  const handleStatusChange = async (alertId, newStatus, domain = '') => {
    const previous = alerts.find((a) => a.id === alertId)?.status || 'OPEN';

    setAlerts((prev) => prev.map((a) => (a.id === alertId ? { ...a, status: newStatus } : a)));
    if (selectedAlert?.id === alertId) {
      setSelectedAlert((prev) => (prev ? { ...prev, status: newStatus } : prev));
    }

    try {
      await api.updateAlertStatus(alertId, newStatus);
      addToast(`${domain || `Alert #${alertId}`}: ${previous} → ${newStatus}`, 'success', 'Status updated');
      fetchAllData(true);
      return true;
    } catch (error) {
      setAlerts((prev) => prev.map((a) => (a.id === alertId ? { ...a, status: previous } : a)));
      if (selectedAlert?.id === alertId) {
        setSelectedAlert((prev) => (prev ? { ...prev, status: previous } : prev));
      }
      addToast(describeError(error), 'error', 'Update failed');
      return false;
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
      fetchAllData(true);
      return true;
    } catch (error) {
      addToast(describeError(error), 'error', 'Save failed');
      return false;
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
  const filteredAlerts = useMemo(() => {
    const searchLower = searchQuery.toLowerCase().trim();
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
          // SEVERITY_ORDER is highest-first, so invert the index to make the
          // descending arrow put Critical above Low (a raw index would reverse it).
          const rank = (value) => {
            const index = SEVERITY_ORDER.indexOf((value || 'LOW').toUpperCase());
            return SEVERITY_ORDER.length - (index === -1 ? SEVERITY_ORDER.length - 1 : index);
          };
          av = rank(av);
          bv = rank(bv);
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
  }, [alerts, filterSeverity, filterStatus, searchQuery, sortConfig]);

  /* ─── Header metrics ──────────────────────────────────────────────────── */
  const stats = useMemo(() => {
    const overview = metricsData?.overview;
    const countBy = (predicate) => alerts.filter(predicate).length;

    return {
      total: toNumber(overview?.total_alerts, alerts.length),
      critical: toNumber(overview?.critical_alerts, countBy((a) => (a.severity || '').toUpperCase() === 'CRITICAL')),
      criticalOpen: toNumber(
        overview?.critical_open_alerts,
        countBy((a) => (a.severity || '').toUpperCase() === 'CRITICAL'
          && ['OPEN', 'INVESTIGATING'].includes((a.status || '').toUpperCase())),
      ),
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
  const handleCopyText = async (text, message = 'Copied to clipboard') => {
    try {
      if (!navigator.clipboard?.writeText) throw new Error('Clipboard API unavailable');
      await navigator.clipboard.writeText(text);
      addToast(message, 'info');
    } catch {
      addToast('Could not access the clipboard. Copy the value manually.', 'warning', 'Clipboard blocked');
    }
  };

  const handleSimulate = async (scenario, count) => {
    try {
      const payload = await api.simulateTraffic(scenario, count);
      const failed = Number(payload.failed) || 0;
      addToast(
        failed ? `${payload.message} ${failed} records failed.` : payload.message,
        failed ? 'warning' : 'success',
        'Traffic injected',
      );
      fetchAllData(true);
      setIncidentRefreshKey((key) => key + 1);
      return payload;
    } catch (error) {
      throw new Error(describeError(error));
    }
  };

  const handleIngestZeek = async () => {
    try {
      const payload = await api.triggerZeekIngest();
      const failed = Number(payload.failed) || 0;
      addToast(
        `${payload.inserted} queries added, ${payload.skipped} duplicates skipped, `
          + `${payload.alerts} alerts, ${payload.incidents} incidents`
          + (failed ? `, ${failed} failed` : ''),
        failed ? 'warning' : 'success',
        'Zeek ingestion',
      );
      fetchAllData(true);
      setIncidentRefreshKey((key) => key + 1);
      return payload;
    } catch (error) {
      throw new Error(describeError(error));
    }
  };

  const handleIngestPcap = async () => {
    try {
      const payload = await api.triggerPcapIngest();
      const failed = Number(payload.failed) || 0;
      addToast(
        `${payload.inserted} queries added, ${payload.skipped} duplicates skipped, `
          + `${payload.alerts} alerts, ${payload.incidents} incidents`
          + (failed ? `, ${failed} failed` : ''),
        failed ? 'warning' : 'success',
        'PCAP analysis',
      );
      fetchAllData(true);
      setIncidentRefreshKey((key) => key + 1);
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
        isLoading={isLoading}
        isRefreshing={isRefreshing}
        onRefresh={() => fetchAllData(true)}
        onOpenSimulator={() => setIsSimulatorOpen(true)}
        onOpenTelemetry={() => setIsTelemetryOpen(true)}
        onExport={handleExport}
        density={density}
        onToggleDensity={toggleDensity}
      />

      {connectionStatus === 'offline' && (
        <div className="offline-banner" role="status">
          <span className="offline-banner-icon">!</span>
          <div className="offline-banner-copy">
            <strong>Live API unavailable — showing fallback data.</strong>
            <span>
              {offlineReason || 'The FastAPI service did not respond.'}
              {' '}Triage actions and exports will fail until it is reachable.
            </span>
          </div>
          <button className="btn-action" onClick={() => fetchAllData()}>
            Retry connection
          </button>
        </div>
      )}

      <nav className="view-tabs" role="tablist" aria-label="Dashboard sections">
        {VIEWS.map((view) => (
          <button
            key={view.key}
            role="tab"
            aria-selected={activeView === view.key}
            className={`view-tab ${activeView === view.key ? 'active' : ''}`}
            onClick={() => {
              if (view.key === activeView) return;
              window.history.pushState(null, '', `#/${view.key}`);
              setActiveView(view.key);
            }}
          >
            {view.label}
            {view.key === 'alerts' && <span className="view-tab-count">{stats.total}</span>}
            {view.key === 'incidents' && <span className="view-tab-count">{stats.incidents}</span>}
            {view.key === 'whitelist' && <span className="view-tab-count">{whitelistCount}</span>}
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
              totalAlerts={alertsTotal || alerts.length}
              filterSeverity={filterSeverity}
              setFilterSeverity={setFilterSeverity}
              filterStatus={filterStatus}
              setFilterStatus={setFilterStatus}
              searchQuery={searchQuery}
              setSearchQuery={setSearchQuery}
              sortConfig={sortConfig}
              onSort={handleSort}
              onStatusChange={handleStatusChange}
              onSelectAlert={openAlert}
              selectedAlertId={selectedAlert?.id}
              density={density}
              isLoading={isLoading}
            />
          </>
        )}

        {activeView === 'incidents' && (
          <IncidentsView
            onNotify={addToast}
            onChanged={() => fetchAllData(true)}
            onSelectIncident={setSelectedIncident}
            refreshSignal={incidentRefreshKey}
          />
        )}

        {activeView === 'whitelist' && (
          <WhitelistView onNotify={addToast} onChanged={() => fetchAllData(true)} />
        )}
      </main>

      <ForensicDrawer
        alert={selectedAlert}
        onClose={closeAlert}
        onUpdateStatus={handleUpdateStatusAndNotes}
        onCopyText={handleCopyText}
      />

      <IncidentDrawer
        incident={selectedIncident}
        onClose={() => setSelectedIncident(null)}
        onNotify={addToast}
        onChanged={(updated) => {
          if (updated) {
            setSelectedIncident((prev) => (prev ? { ...prev, ...updated } : prev));
          }
          fetchAllData(true);
          setIncidentRefreshKey((key) => key + 1);
        }}
        onViewAlert={(alertId) => {
          setSelectedIncident(null);
          openAlert(alertId);
        }}
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
        onOpenAlert={(alertId) => {
          setIsTelemetryOpen(false);
          openAlert(alertId);
        }}
      />

      <footer className="soc-footer">
        <div className="footer-left">
          <span>HCL · DNS Tunneling Detection</span>
          <span className="footer-sep">/</span>
          <span>{stats.total} alerts · {stats.activeIncidents} active incidents</span>
        </div>
        <div className="footer-right">
          <span>Times in UTC</span>
          <span className="footer-sep">/</span>
          <span>Refresh in <strong>{countdown}s</strong></span>
          {activeView === 'alerts' && (
            <>
              <span className="footer-sep">/</span>
              <span><kbd>Ctrl</kbd>+<kbd>K</kbd> search</span>
            </>
          )}
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
