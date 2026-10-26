import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  ActivityIcon,
  ChevronRightIcon,
  ClockIcon,
  RefreshIcon,
  SearchIcon,
  UserIcon,
  XIcon,
} from './Icons';
import { api, describeError } from '../services/api';
import { formatDateTime, initials, slaFor, timeAgo } from '../utils/format';

const SEVERITY_COLORS = {
  CRITICAL: '#d3564f',
  HIGH:     '#cf8748',
  MEDIUM:   '#6b8fb5',
  LOW:      '#7fa583',
};

const STATUS_STYLES = {
  OPEN:             { color: '#d3564f', bg: 'rgba(211,86,79,0.12)' },
  INVESTIGATING:    { color: '#cf8748', bg: 'rgba(207,135,72,0.12)' },
  CONTAINED:        { color: '#6b8fb5', bg: 'rgba(107,143,181,0.12)' },
  RESOLVED:         { color: '#7fa583', bg: 'rgba(127,165,131,0.12)' },
  'FALSE POSITIVE': { color: '#6b6b76', bg: 'rgba(107,107,118,0.12)' },
  CLOSED:           { color: '#6b6b76', bg: 'rgba(107,107,118,0.12)' },
};

const INCIDENT_STATUSES = ['OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE POSITIVE', 'CLOSED'];
const ACTIVE_STATUSES = ['OPEN', 'INVESTIGATING', 'CONTAINED'];
const TERMINAL_STATUSES = ['RESOLVED', 'FALSE POSITIVE', 'CLOSED'];

function statusStyle(status) {
  return STATUS_STYLES[(status || 'OPEN').toUpperCase()] || STATUS_STYLES.OPEN;
}

function isUnassigned(owner) {
  return !owner || owner.trim().toLowerCase() === 'unassigned';
}

export function IncidentsView({ onNotify, onChanged, onSelectIncident, refreshSignal = 0 }) {
  const [incidents, setIncidents] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [busyId, setBusyId] = useState(null);
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [search, setSearch] = useState('');
  const [error, setError] = useState(null);
  const lastSignalRef = useRef(refreshSignal);

  const load = useCallback(async (quiet = false) => {
    if (!quiet) {
      setIsLoading(true);
      setError(null);
    } else {
      setIsRefreshing(true);
    }
    try {
      const payload = await api.getIncidents();
      setIncidents(payload.data || []);
      setError(null);
    } catch (err) {
      // Keep the last known queue visible; a transient refresh failure should
      // not blank the analyst's working set.
      setError(describeError(err));
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  // The case drawer can update status, owner, or notes outside this component.
  // Reload the queue when the parent says a save completed.
  useEffect(() => {
    if (refreshSignal === lastSignalRef.current) return;
    lastSignalRef.current = refreshSignal;
    load(true);
  }, [refreshSignal, load]);

  const patchIncident = async (incident, patch) => {
    const previous = incident.status;
    setBusyId(incident.id);
    setIncidents((prev) => prev.map((item) => (
      item.id === incident.id ? { ...item, ...patch } : item
    )));

    try {
      await api.updateIncident(incident.id, patch);
      onNotify?.(`INC-${String(incident.id).padStart(4, '0')} moved to ${patch.status}`, 'success');
      onChanged?.();
    } catch (err) {
      setIncidents((prev) => prev.map((item) => (
        item.id === incident.id ? { ...item, status: previous } : item
      )));
      onNotify?.(describeError(err), 'error', 'Update failed');
    } finally {
      setBusyId(null);
    }
  };

  const searchTerm = search.trim().toLowerCase();

  const visible = useMemo(() => incidents.filter((incident) => {
    const status = (incident.status || 'OPEN').toUpperCase();
    const severity = (incident.severity || '').toUpperCase();

    if (statusFilter !== 'ALL' && status !== statusFilter) return false;
    if (severityFilter !== 'ALL' && severity !== severityFilter) return false;

    if (!searchTerm) return true;

    return [
      `inc-${incident.id}`,
      String(incident.id),
      incident.domain,
      incident.source_ip,
      incident.assigned_to,
      incident.detection_reason,
    ].some((value) => String(value || '').toLowerCase().includes(searchTerm));
  }), [incidents, statusFilter, severityFilter, searchTerm]);

  const summary = (() => {
    const active = incidents.filter((incident) => ACTIVE_STATUSES.includes((incident.status || 'OPEN').toUpperCase()));
    const unassigned = incidents.filter((incident) => (
      !TERMINAL_STATUSES.includes((incident.status || 'OPEN').toUpperCase())
      && isUnassigned(incident.assigned_to)
    ));
    const overdue = incidents.filter((incident) => (
      !TERMINAL_STATUSES.includes((incident.status || 'OPEN').toUpperCase())
      && slaFor(incident.severity, incident.created_at).state === 'overdue'
    ));

    return { active: active.length, unassigned: unassigned.length, overdue: overdue.length };
  })();

  const hasFilters = statusFilter !== 'ALL' || severityFilter !== 'ALL' || search.trim() !== '';

  const clearFilters = () => {
    setStatusFilter('ALL');
    setSeverityFilter('ALL');
    setSearch('');
  };

  return (
    <div className="panel incidents-panel">
      <div className="incident-toolbar">
        <div>
          <h3>Escalated incidents</h3>
          <p className="panel-sub">
            Cases opened automatically when an alert scores High or Critical.
            The response clock starts when the case is created.
          </p>
        </div>

        <div className="incident-headline-stats">
          <div className="incident-headline-stat">
            <ActivityIcon size={12} />
            <strong>{summary.active}</strong>
            <span>active</span>
          </div>
          <div className="incident-headline-stat">
            <UserIcon size={12} />
            <strong>{summary.unassigned}</strong>
            <span>unassigned</span>
          </div>
          <div className={`incident-headline-stat ${summary.overdue > 0 ? 'warn' : ''}`}>
            <ClockIcon size={12} />
            <strong>{summary.overdue}</strong>
            <span>past SLA</span>
          </div>
        </div>
      </div>

      <div className="incident-filter-bar">
        <div className="incident-search">
          <SearchIcon size={13} className="search-icon" />
          <input
            type="text"
            className="table-search"
            placeholder="Search case, domain, source IP, or owner…"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            aria-label="Search incidents"
          />
          {search && (
            <button className="search-clear-btn" onClick={() => setSearch('')} aria-label="Clear incident search">
              <XIcon size={12} />
            </button>
          )}
        </div>

        <select
          className="filter-select"
          value={statusFilter}
          onChange={(event) => setStatusFilter(event.target.value)}
          aria-label="Filter incidents by status"
        >
          <option value="ALL">All statuses</option>
          {INCIDENT_STATUSES.map((status) => (
            <option key={status} value={status}>{status}</option>
          ))}
        </select>

        <select
          className="filter-select"
          value={severityFilter}
          onChange={(event) => setSeverityFilter(event.target.value)}
          aria-label="Filter incidents by severity"
        >
          <option value="ALL">All severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>

        {hasFilters && (
          <button className="btn-clear-filter" onClick={clearFilters}>
            Reset filters
          </button>
        )}

        <div className="incident-filter-actions">
          <div className="table-count-badge">
            <strong>{visible.length}</strong>
            <span>of {incidents.length} cases</span>
          </div>

          <button
            className="btn-action"
            onClick={() => load(incidents.length > 0)}
            disabled={isLoading || isRefreshing}
          >
            <RefreshIcon size={12} className={isLoading || isRefreshing ? 'spin-anim' : ''} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {error && incidents.length > 0 && (
        <div className="inline-warning incident-inline-error" role="alert">
          <span>Queue refresh failed: {error}</span>
          <button className="section-link" onClick={() => load(true)}>Retry</button>
        </div>
      )}

      {error && incidents.length === 0 ? (
        <div className="table-empty-wrap">
          <span>Could not load incidents: {error}</span>
          <button className="btn-action primary" onClick={() => load()}>Retry</button>
        </div>
      ) : isLoading ? (
        <div className="table-loading-wrap">
          <div className="table-spinner" />
          <span>Loading incident queue…</span>
        </div>
      ) : visible.length === 0 ? (
        <div className="table-empty-wrap">
          <ActivityIcon size={26} color="var(--text-dim)" />
          <p>
            {incidents.length === 0
              ? 'No incidents yet. Ingest a log or run a simulation to generate High or Critical alerts.'
              : 'No cases match the current filters.'}
          </p>
          {hasFilters && incidents.length > 0 && (
            <button className="btn-action primary" onClick={clearFilters}>Clear filters</button>
          )}
        </div>
      ) : (
        <>
          <div className="incident-column-head" aria-hidden="true">
            <span>Case</span>
            <span>Severity</span>
            <span>Target</span>
            <span>Owner</span>
            <span>Response SLA</span>
            <span>Status</span>
            <span />
          </div>

          <div className="incident-list">
            {visible.map((incident) => {
              const severity = (incident.severity || 'MEDIUM').toUpperCase();
              const sevColor = SEVERITY_COLORS[severity] || SEVERITY_COLORS.MEDIUM;
              const status = (incident.status || 'OPEN').toUpperCase();
              const currentStatus = statusStyle(status);
              const owner = incident.assigned_to || 'Unassigned';
              const sla = slaFor(incident.severity, incident.created_at, Date.now(), status);

              return (
                <div
                  className="incident-row"
                  key={incident.id}
                  onClick={() => onSelectIncident?.(incident)}
                  onKeyDown={(event) => {
                    if (event.target !== event.currentTarget) return;
                    if (event.key === 'Enter' || event.key === ' ') {
                      event.preventDefault();
                      onSelectIncident?.(incident);
                    }
                  }}
                  tabIndex={0}
                  aria-label={`Open incident ${incident.id} for ${incident.domain}`}
                  title="Open case detail"
                >
                  <span className="incident-id mono">
                    INC-{String(incident.id).padStart(4, '0')}
                  </span>

                  <span
                    className="badge-severity"
                    style={{ borderColor: `${sevColor}55`, color: sevColor, background: `${sevColor}14` }}
                  >
                    <span className="sev-dot" style={{ background: sevColor }} />
                    {severity}
                  </span>

                  <div className="incident-main">
                    <div className="incident-domain" title={incident.domain}>
                      {incident.domain}
                    </div>
                    <div className="incident-sub">
                      <span className="mono">alert #{incident.alert_id}</span>
                      <span className="incident-dot">·</span>
                      score {incident.risk_score}
                      <span className="incident-dot">·</span>
                      {timeAgo(incident.created_at)}
                    </div>
                  </div>

                  <div className="incident-owner">
                    <span className={`avatar avatar-sm ${isUnassigned(owner) ? 'avatar-empty' : ''}`}>
                      {initials(owner)}
                    </span>
                    <span className="incident-owner-copy">
                      <span className={`incident-owner-name ${isUnassigned(owner) ? 'unassigned' : ''}`}>
                        {owner}
                      </span>
                      <span className="incident-owner-meta mono">
                        {incident.source_ip || 'source unknown'}
                      </span>
                    </span>
                  </div>

                  <div
                    className={`incident-sla ${sla.state}`}
                    title={sla.state === 'closed' ? 'Response clock stopped' : `Due ${formatDateTime(sla.dueAt)}`}
                  >
                    <span className={`sla-dot ${sla.state}`} aria-hidden="true" />
                    <span className="incident-sla-copy">
                      <strong>{sla.label}</strong>
                      <span>
                        {sla.state === 'closed'
                          ? 'clock stopped'
                          : sla.dueAt ? `due ${formatDateTime(sla.dueAt)}` : 'no timestamp'}
                      </span>
                    </span>
                  </div>

                  <select
                    className="incident-status-select"
                    value={status}
                    disabled={busyId === incident.id}
                    style={{ color: currentStatus.color, borderColor: `${currentStatus.color}55`, background: currentStatus.bg }}
                    onClick={(event) => event.stopPropagation()}
                    onKeyDown={(event) => event.stopPropagation()}
                    onChange={(event) => patchIncident(incident, { status: event.target.value })}
                    aria-label={`Status for incident ${incident.id}`}
                  >
                    {INCIDENT_STATUSES.map((option) => (
                      <option key={option} value={option}>{option}</option>
                    ))}
                  </select>

                  <button
                    className="incident-open-btn"
                    onClick={(event) => {
                      event.stopPropagation();
                      onSelectIncident?.(incident);
                    }}
                    aria-label={`Open incident ${incident.id}`}
                  >
                    <ChevronRightIcon size={14} />
                  </button>
                </div>
              );
            })}
          </div>
        </>
      )}
    </div>
  );
}
