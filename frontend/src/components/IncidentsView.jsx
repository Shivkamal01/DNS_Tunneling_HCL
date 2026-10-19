import React, { useCallback, useEffect, useState } from 'react';
import { ActivityIcon, RefreshIcon } from './Icons';
import { api, describeError } from '../services/api';

const SEVERITY_COLORS = {
  CRITICAL: '#d3564f',
  HIGH:     '#cf8748',
  MEDIUM:   '#6b8fb5',
  LOW:      '#7fa583',
};

const STATUS_STYLES = {
  OPEN:           { color: '#d3564f', bg: 'rgba(211,86,79,0.12)' },
  INVESTIGATING:  { color: '#cf8748', bg: 'rgba(207,135,72,0.12)' },
  CONTAINED:      { color: '#6b8fb5', bg: 'rgba(107,143,181,0.12)' },
  RESOLVED:       { color: '#7fa583', bg: 'rgba(127,165,131,0.12)' },
  'FALSE POSITIVE': { color: '#6b6b76', bg: 'rgba(107,107,118,0.12)' },
  CLOSED:         { color: '#6b6b76', bg: 'rgba(107,107,118,0.12)' },
};

const INCIDENT_STATUSES = ['OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE POSITIVE'];

function formatWhen(value) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleString('en-US', {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false,
  });
}

export function IncidentsView({ onNotify, onChanged }) {
  const [incidents, setIncidents] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [busyId, setBusyId] = useState(null);
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [error, setError] = useState(null);

  const load = useCallback(async (quiet = false) => {
    if (!quiet) setIsLoading(true);
    setError(null);
    try {
      const payload = await api.getIncidents();
      setIncidents(payload.data || []);
    } catch (err) {
      setError(describeError(err));
      setIncidents([]);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const patchIncident = async (incident, patch) => {
    setBusyId(incident.id);
    try {
      await api.updateIncident(incident.id, patch);
      setIncidents((prev) => prev.map((item) => (
        item.id === incident.id ? { ...item, ...patch } : item
      )));
      onNotify?.(`Incident #${incident.id} updated`, 'success');
      onChanged?.();
    } catch (err) {
      onNotify?.(describeError(err), 'error', 'Update failed');
    } finally {
      setBusyId(null);
    }
  };

  const visible = incidents.filter(
    (incident) => statusFilter === 'ALL' || (incident.status || '').toUpperCase() === statusFilter,
  );

  return (
    <div className="panel">
      <div className="incident-toolbar">
        <div>
          <h3 style={{ fontSize: 12, fontWeight: 600 }}>Escalated incidents</h3>
          <p className="panel-sub">
            Opened automatically when an alert scores High or Critical
          </p>
        </div>

        <div className="toolbar-right">
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

          <div className="table-count-badge">
            <strong>{visible.length}</strong>
            <span>of {incidents.length}</span>
          </div>

          <button className="btn-action" onClick={() => load()} disabled={isLoading}>
            <RefreshIcon size={12} className={isLoading ? 'spin-anim' : ''} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {error ? (
        <div className="table-empty-wrap">
          <span>Could not load incidents: {error}</span>
          <button className="btn-action primary" onClick={() => load()}>Retry</button>
        </div>
      ) : isLoading ? (
        <div className="table-loading-wrap">
          <div className="table-spinner" />
          <span>Loading incidents…</span>
        </div>
      ) : visible.length === 0 ? (
        <div className="table-empty-wrap">
          <ActivityIcon size={26} color="#3a3a44" />
          <p>
            {incidents.length === 0
              ? 'No incidents yet. Ingest a log or run a simulation to generate High/Critical alerts.'
              : 'No incidents match this filter.'}
          </p>
        </div>
      ) : (
        <div className="incident-list">
          {visible.map((incident) => {
            const severity = (incident.severity || 'MEDIUM').toUpperCase();
            const sevColor = SEVERITY_COLORS[severity] || SEVERITY_COLORS.MEDIUM;
            const status = (incident.status || 'OPEN').toUpperCase();
            const statusStyle = STATUS_STYLES[status] || STATUS_STYLES.OPEN;

            return (
              <div
                className="incident-row"
                key={incident.id}
                onClick={() => {
                  // Quick action: assigning to yourself is the most common
                  // triage step, so a row click does it rather than opening a
                  // detail pane that does not exist yet.
                  if (!incident.assigned_to || incident.assigned_to === 'Unassigned') {
                    patchIncident(incident, { assigned_to: 'SOC Analyst (Tier-1)' });
                  }
                }}
                title={
                  !incident.assigned_to || incident.assigned_to === 'Unassigned'
                    ? 'Click to assign to yourself'
                    : undefined
                }
              >
                <div className="incident-id">INC-{String(incident.id).padStart(4, '0')}</div>

                <div className="incident-main">
                  <div className="incident-domain">{incident.domain}</div>
                  <div className="incident-sub">
                    score {incident.risk_score} · {incident.detection_reason || 'Elevated risk'}
                    {' · '}{formatWhen(incident.created_at)}
                  </div>
                </div>

                <div className="incident-assignee">
                  <span className="incident-label">Owner</span>
                  <span className="incident-assignee-name">
                    {incident.assigned_to || 'Unassigned'}
                  </span>
                </div>

                <select
                  className="incident-status-select"
                  value={status}
                  disabled={busyId === incident.id}
                  style={{ color: statusStyle.color, borderColor: `${statusStyle.color}55`, background: statusStyle.bg }}
                  onClick={(event) => event.stopPropagation()}
                  onChange={(event) => patchIncident(incident, { status: event.target.value })}
                  aria-label={`Status for incident ${incident.id}`}
                >
                  {INCIDENT_STATUSES.map((option) => (
                    <option key={option} value={option}>{option}</option>
                  ))}
                </select>

                <span
                  className="badge-severity"
                  style={{ borderColor: `${sevColor}55`, color: sevColor, background: `${sevColor}14` }}
                >
                  <span className="sev-dot" style={{ background: sevColor }} />
                  {severity}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
