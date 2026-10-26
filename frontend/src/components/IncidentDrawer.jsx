import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { api, describeError } from '../services/api';
import {
  formatBytes,
  formatDateTime,
  initials,
  ipContext,
  slaFor,
  timeAgo,
} from '../utils/format';
import { PRIMARY_TECHNIQUES } from '../utils/techniques';
import {
  useBodyScrollLock,
  useEscapeKey,
  useFocusReturn,
  useFocusTrap,
} from '../utils/overlay';
import {
  ActivityIcon,
  CheckCircleIcon,
  ChevronRightIcon,
  ClockIcon,
  ExternalLinkIcon,
  ShieldIcon,
  UserIcon,
  XIcon,
} from './Icons';

const SEVERITY_COLORS = {
  CRITICAL: '#d3564f',
  HIGH:     '#cf8748',
  MEDIUM:   '#6b8fb5',
  LOW:      '#7fa583',
};

const INCIDENT_STATUSES = ['OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE POSITIVE', 'CLOSED'];

const STATUS_STYLES = {
  OPEN:             { color: '#d3564f', bg: 'rgba(211,86,79,0.12)' },
  INVESTIGATING:    { color: '#cf8748', bg: 'rgba(207,135,72,0.12)' },
  CONTAINED:        { color: '#6b8fb5', bg: 'rgba(107,143,181,0.12)' },
  RESOLVED:         { color: '#7fa583', bg: 'rgba(127,165,131,0.12)' },
  'FALSE POSITIVE': { color: '#6b6b76', bg: 'rgba(107,107,118,0.12)' },
  CLOSED:           { color: '#6b6b76', bg: 'rgba(107,107,118,0.12)' },
};

const ANALYST_ROSTER = [
  'SOC Analyst (Tier-1)',
  'M. Okafor (Tier-2)',
  'J. Alvarez (Tier-2)',
  'S. Raman (Incident Response)',
];

function normalizeOwner(value) {
  return !value || value === 'Unassigned' ? '' : value;
}

function statusStyle(status) {
  return STATUS_STYLES[(status || 'OPEN').toUpperCase()] || STATUS_STYLES.OPEN;
}

export function IncidentDrawer({
  incident,
  onClose,
  onNotify,
  onChanged,
  onViewAlert,
}) {
  const drawerRef = useRef(null);
  const discardRef = useRef(null);
  const [status, setStatus] = useState('OPEN');
  const [owner, setOwner] = useState('');
  const [notes, setNotes] = useState('');
  const [baseline, setBaseline] = useState({ status: 'OPEN', owner: '', notes: '' });
  const [alertDetail, setAlertDetail] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState(null);
  const [isSaving, setIsSaving] = useState(false);
  const [discardIntent, setDiscardIntent] = useState(null);

  useBodyScrollLock(Boolean(incident));
  useFocusReturn(Boolean(incident), drawerRef);
  useFocusTrap(Boolean(incident), drawerRef);
  useFocusTrap(Boolean(discardIntent), discardRef);

  // Reset the form whenever a different case is selected. The drawer stays
  // mounted between selections, so without this the previous analyst's notes
  // would leak into the next case.
  useEffect(() => {
    if (!incident) return;

    const safeStatus = (incident.status || 'OPEN').toUpperCase();
    const safeOwner = normalizeOwner(incident.assigned_to);
    const safeNotes = incident.analyst_notes || '';

    setStatus(safeStatus);
    setOwner(safeOwner);
    setNotes(safeNotes);
    setBaseline({ status: safeStatus, owner: safeOwner, notes: safeNotes });
    setDiscardIntent(null);
  }, [incident]);

  // The incident row only carries a summary. Pull the full alert record so the
  // drawer can show the feature vector and the indicators behind the score.
  useEffect(() => {
    if (!incident?.alert_id) {
      setAlertDetail(null);
      setDetailError(null);
      setDetailLoading(false);
      return undefined;
    }

    let cancelled = false;
    setAlertDetail(null);
    setDetailLoading(true);
    setDetailError(null);

    api.getAlertDetail(incident.alert_id)
      .then((payload) => {
        if (!cancelled && payload?.data) setAlertDetail(payload.data);
      })
      .catch((error) => {
        if (!cancelled) setDetailError(describeError(error));
      })
      .finally(() => {
        if (!cancelled) setDetailLoading(false);
      });

    return () => { cancelled = true; };
  }, [incident?.alert_id]);

  const dirty = Boolean(incident) && (
    status !== baseline.status
    || owner.trim() !== baseline.owner.trim()
    || notes !== baseline.notes
  );

  const requestClose = useCallback(() => {
    if (dirty) {
      setDiscardIntent('close');
      return;
    }
    onClose();
  }, [dirty, onClose]);

  const cancelDiscard = () => {
    setDiscardIntent(null);
    // The dialog's Keep editing button disappears when the overlay closes, so
    // move focus back to a stable control in the drawer rather than the body.
    drawerRef.current?.querySelector('.drawer-close-btn')?.focus();
  };

  useEscapeKey(Boolean(incident), () => {
    if (discardIntent) {
      cancelDiscard();
      return;
    }
    requestClose();
  });

  const openLinkedAlert = () => {
    if (!incident?.alert_id || !onViewAlert) return;
    if (dirty) {
      setDiscardIntent('alert');
      return;
    }
    onClose();
    onViewAlert(incident.alert_id);
  };

  const confirmDiscard = () => {
    const intent = discardIntent;
    setDiscardIntent(null);

    if (intent === 'alert' && incident?.alert_id && onViewAlert) {
      onClose();
      onViewAlert(incident.alert_id);
      return;
    }
    onClose();
  };

  const handleSave = async () => {
    if (!incident || isSaving || !dirty) return;

    setIsSaving(true);
    try {
      await api.updateIncident(incident.id, {
        status,
        assigned_to: owner.trim() || 'Unassigned',
        analyst_notes: notes,
      });

      const saved = { status, owner: owner.trim(), notes };
      setBaseline(saved);
      setOwner(saved.owner);
      onNotify?.(`INC-${String(incident.id).padStart(4, '0')} updated`, 'success', 'Case saved');
      onChanged?.({
        status,
        assigned_to: saved.owner || 'Unassigned',
        analyst_notes: notes,
        updated_at: new Date().toISOString(),
      });
    } catch (error) {
      onNotify?.(describeError(error), 'error', 'Could not save case');
    } finally {
      setIsSaving(false);
    }
  };

  const resetFields = () => {
    setStatus(baseline.status);
    setOwner(baseline.owner);
    setNotes(baseline.notes);
  };

  const detail = alertDetail;

  const sourceIp = detail?.source_ip || incident?.source_ip || '';
  const network = useMemo(() => ipContext(sourceIp), [sourceIp]);
  // Keep the SLA live while the drawer is open; the parent refresh loop causes
  // a render every second, so this value should not be memoised against time.
  const sla = slaFor(
    incident?.severity,
    incident?.created_at || detail?.created_at,
    Date.now(),
    incident?.status,
  );
  const domain = detail?.domain || incident?.domain || '';
  const severity = (incident?.severity || detail?.severity || 'MEDIUM').toUpperCase();
  const sevColor = SEVERITY_COLORS[severity] || SEVERITY_COLORS.MEDIUM;
  const currentStatusStyle = statusStyle(status);

  const timeline = useMemo(() => {
    if (!incident) return [];
    const openedAt = incident.created_at ? new Date(incident.created_at).getTime() : null;
    const updatedAt = incident.updated_at ? new Date(incident.updated_at).getTime() : null;
    // The initial insert sets both timestamps. Only show a separate update
    // event once an analyst has actually changed the case.
    const showUpdate = Boolean(
      updatedAt && openedAt && updatedAt - openedAt > 1000
    );
    return [
      detail?.query_time && { at: detail.query_time, label: 'DNS query observed', tone: 'muted' },
      detail?.created_at && { at: detail.created_at, label: 'Detection raised alert', tone: 'alert' },
      incident.created_at && { at: incident.created_at, label: 'Case opened for triage', tone: 'case' },
      showUpdate && { at: incident.updated_at, label: 'Last case update', tone: 'muted' },
    ].filter(Boolean);
  }, [incident, detail]);

  if (!incident) return null;

  const indicators = detail?.indicator_list || [];

  return (
    <div className="drawer-backdrop" onClick={requestClose}>
      <aside
        className="forensic-drawer incident-drawer"
        ref={drawerRef}
        tabIndex={-1}
        onClick={(event) => event.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-labelledby="incident-drawer-title"
      >
        <div className="drawer-header">
          <div className="drawer-header-left">
            <span className="drawer-tag mono">INC-{String(incident.id).padStart(4, '0')}</span>
            <span
              className="badge-severity"
              style={{ borderColor: `${sevColor}44`, color: sevColor, background: `${sevColor}14` }}
            >
              <span className="sev-dot" style={{ background: sevColor }} />
              {severity}
            </span>
            <span
              className="status-chip"
              style={{ color: currentStatusStyle.color, background: currentStatusStyle.bg }}
            >
              {status}
            </span>
          </div>

          <button className="drawer-close-btn" onClick={requestClose} aria-label="Close incident">
            <XIcon size={18} />
          </button>
        </div>

        <div className="drawer-body">
          <section className="forensic-section">
            <div className="case-summary-card" style={{ borderLeftColor: sevColor }}>
              <div className="case-summary-top">
                <div>
                  <span className="case-eyebrow">Escalated case</span>
                  <h3 id="incident-drawer-title" className="case-domain mono" title={domain}>{domain || 'Unknown target'}</h3>
                </div>
                <span className="case-age mono" title={formatDateTime(incident.created_at)}>
                  opened {timeAgo(incident.created_at)}
                </span>
              </div>

              <p className="case-reason">
                {detail?.detection_reason || incident.detection_reason || 'Elevated risk score'}
              </p>

              <div className="case-stat-grid">
                <div className="case-stat">
                  <span className="case-stat-label">Risk score</span>
                  <strong className="mono" style={{ color: sevColor }}>
                    {incident.risk_score ?? detail?.risk_score ?? '—'}<span className="case-stat-unit">/100</span>
                  </strong>
                </div>
                <div className="case-stat">
                  <span className="case-stat-label">Linked alert</span>
                  <strong className="mono">
                    {incident.alert_id ? `#${String(incident.alert_id).padStart(4, '0')}` : '—'}
                  </strong>
                </div>
                <div className="case-stat">
                  <span className="case-stat-label">Owner</span>
                  <strong className="case-owner-value">
                    {owner.trim() || 'Unassigned'}
                  </strong>
                </div>
                <div className="case-stat">
                  <span className="case-stat-label">Opened</span>
                  <strong className="mono case-stat-time">{formatDateTime(incident.created_at)}</strong>
                </div>
              </div>
            </div>
          </section>

          <section className="forensic-section">
            <div className={`sla-banner ${sla.state}`}>
              <ClockIcon size={16} />
              <div className="sla-copy">
                <span className="sla-title">
                  Response SLA · {sla.hours}h for {sla.level}
                </span>
                <strong>{sla.label}</strong>
                <span className="sla-due">
                  {sla.state === 'closed'
                    ? 'Response clock stopped'
                    : sla.dueAt ? `Due ${formatDateTime(sla.dueAt)}` : 'No timestamp available'}
                </span>
              </div>
            </div>
          </section>

          <section className="forensic-section">
            <div className="section-title">
              <ActivityIcon size={15} color="#d9a04a" />
              <h4>Linked alert &amp; network context</h4>
              {incident.alert_id && onViewAlert && (
                <button className="section-link" onClick={openLinkedAlert}>
                  Open full alert
                  <ChevronRightIcon size={12} />
                </button>
              )}
            </div>

            {detailError && (
              <div className="inline-warning">
                Full alert detail unavailable ({detailError}). Showing the incident record.
              </div>
            )}

            <div className="alert-context-grid">
              <div className="context-item">
                <span className="meta-label">Source client</span>
                <span className="meta-val mono">{sourceIp || '—'}</span>
                <span className="context-note">
                  {network.label}{network.subnet !== '—' ? ` · ${network.subnet}` : ''}
                </span>
              </div>
              <div className="context-item">
                <span className="meta-label">Record type</span>
                <span className="meta-val mono">{detail?.qtype_name || incident.qtype_name || 'A'}</span>
                <span className="context-note">
                  {detail?.ttl ? `TTL ${detail.ttl}s` : 'No answer TTL (query only)'}
                </span>
              </div>
              <div className="context-item">
                <span className="meta-label">Query length</span>
                <span className="meta-val mono">
                  {detail?.query_length ?? detail?.domain?.length ?? '—'}
                  {(detail?.query_length ?? detail?.domain?.length) ? ' chars' : ''}
                </span>
                <span className="context-note">
                  {detailLoading
                    ? 'Feature detail pending'
                    : detail?.subdomain_length
                      ? `${detail.subdomain_length} in subdomain`
                      : 'Full QNAME'}
                </span>
              </div>
              <div className="context-item">
                <span className="meta-label">Shannon entropy</span>
                <span className="meta-val mono">
                  {typeof detail?.entropy === 'number' ? detail.entropy.toFixed(3) : '—'}
                </span>
                <span className="context-note">
                  {typeof detail?.entropy_ratio === 'number'
                    ? `${Math.round(detail.entropy_ratio * 100)}% of length ceiling`
                    : 'Length-normalised ratio unavailable'}
                </span>
              </div>
              <div className="context-item">
                <span className="meta-label">Estimated payload</span>
                <span className="meta-val mono">
                  {typeof detail?.est_payload_bytes === 'number'
                    ? formatBytes(detail.est_payload_bytes)
                    : '—'}
                </span>
                <span className="context-note">Encoded bytes in label stream</span>
              </div>
              <div className="context-item">
                <span className="meta-label">Query observed</span>
                <span className="meta-val mono">
                  {detail?.query_time ? formatDateTime(detail.query_time) : '—'}
                </span>
                <span className="context-note">
                  {detail?.query_time ? timeAgo(detail.query_time) : 'Awaiting alert detail'}
                </span>
              </div>
            </div>

            {detailLoading && (
              <div className="detail-loading">
                <div className="table-spinner" />
                <span>Loading alert feature vector…</span>
              </div>
            )}

            {indicators.length > 0 && (
              <div className="indicators-list context-indicators">
                {indicators.map((indicator, index) => (
                  <div key={`${indicator}-${index}`} className="indicator-pill">
                    <span className="indicator-bullet">•</span>
                    <span>{indicator}</span>
                  </div>
                ))}
              </div>
            )}
          </section>

          <section className="forensic-section">
            <div className="section-title">
              <ShieldIcon size={15} color="#cf8748" />
              <h4>Technique mapping</h4>
            </div>

            <div className="mitre-grid">
              {PRIMARY_TECHNIQUES.map((technique) => (
                <a
                  key={technique.id}
                  className="mitre-card"
                  href={technique.url}
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  <span className="mitre-id mono">{technique.id}</span>
                  <span className="mitre-name">{technique.name}</span>
                  <span className="mitre-tactic">{technique.tactic}</span>
                  <ExternalLinkIcon size={11} className="mitre-link-icon" />
                </a>
              ))}
            </div>
            <p className="fine-print">
              Techniques describe the observed behaviour, not confirmed attribution.
              Validate against endpoint and resolver telemetry before escalation.
            </p>
          </section>

          <section className="forensic-section">
            <div className="section-title">
              <ClockIcon size={15} color="#94a3b8" />
              <h4>Case timeline</h4>
            </div>

            <div className="case-timeline">
              {timeline.map((event) => (
                <div className="timeline-item" key={`${event.label}-${event.at}`}>
                  <span className={`timeline-dot ${event.tone}`} aria-hidden="true" />
                  <span className="timeline-label">{event.label}</span>
                  <span className="timeline-time mono">{formatDateTime(event.at)}</span>
                </div>
              ))}
            </div>
          </section>

          <section className="forensic-section triage-section">
            <div className="section-title">
              <CheckCircleIcon size={15} color="#d9a04a" />
              <h4>Case disposition</h4>
              {dirty && <span className="unsaved-pill">Unsaved</span>}
            </div>

            <div className="triage-controls">
              <div className="control-row">
                <div className="control-group">
                  <label className="control-label" htmlFor="incident-status">Status</label>
                  <select
                    id="incident-status"
                    className="triage-status-select"
                    style={{
                      color: currentStatusStyle.color,
                      borderColor: `${currentStatusStyle.color}55`,
                      background: currentStatusStyle.bg,
                    }}
                    value={status}
                    onChange={(event) => setStatus(event.target.value)}
                    disabled={isSaving}
                  >
                    {INCIDENT_STATUSES.map((option) => (
                      <option key={option} value={option}>{option}</option>
                    ))}
                  </select>
                </div>

                <div className="control-group control-grow">
                  <label className="control-label" htmlFor="incident-owner">Owner</label>
                  <div className="owner-input-row">
                    <span className="avatar avatar-md" aria-hidden="true">{initials(owner)}</span>
                    <input
                      id="incident-owner"
                      className="text-input"
                      list="incident-analyst-roster"
                      placeholder="Unassigned"
                      value={owner}
                      maxLength={100}
                      onChange={(event) => setOwner(event.target.value)}
                      autoComplete="off"
                      disabled={isSaving}
                    />
                    <datalist id="incident-analyst-roster">
                      {ANALYST_ROSTER.map((name) => <option key={name} value={name} />)}
                    </datalist>
                    <button
                      type="button"
                      className="btn-action btn-small"
                      onClick={() => setOwner('SOC Analyst (Tier-1)')}
                      title="Assign this case to the signed-in analyst"
                      disabled={isSaving}
                    >
                      <UserIcon size={11} />
                      Assign me
                    </button>
                  </div>
                </div>
              </div>

              <div className="control-group">
                <div className="control-label-row">
                  <label className="control-label" htmlFor="incident-notes">Case notes</label>
                  <span className="char-count">{notes.length}/4000</span>
                </div>
                <textarea
                  id="incident-notes"
                  className="triage-notes-area"
                  rows={5}
                  maxLength={4000}
                  placeholder="Record containment actions, host owner confirmation, resolver evidence, or the reason this is benign…"
                  value={notes}
                  onChange={(event) => setNotes(event.target.value)}
                  disabled={isSaving}
                  onKeyDown={(event) => {
                    if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
                      event.preventDefault();
                      handleSave();
                    }
                  }}
                />
                <span className="control-hint">Ctrl+Enter saves. Notes are stored against the case, not the alert.</span>
              </div>
            </div>
          </section>
        </div>

        <div className="drawer-footer">
          <span className={`save-state ${dirty ? 'dirty' : ''}`}>
            {dirty ? 'Unsaved changes' : 'All changes saved'}
          </span>
          <div className="drawer-footer-actions">
            {dirty && (
              <button className="btn-action" onClick={resetFields} disabled={isSaving}>
                Reset
              </button>
            )}
            <button className="btn-action" onClick={requestClose} disabled={isSaving}>
              Close
            </button>
            <button
              className="btn-action primary"
              onClick={handleSave}
              disabled={!dirty || isSaving}
            >
              {isSaving ? 'Saving…' : 'Save case'}
            </button>
          </div>
        </div>

        {discardIntent && (
          <div className="discard-overlay" role="alertdialog" aria-modal="true" aria-labelledby="discard-title">
            <div className="discard-card" ref={discardRef} tabIndex={-1}>
              <h5 id="discard-title">Discard unsaved changes?</h5>
              <p>
                {discardIntent === 'alert'
                  ? 'Opening the linked alert will leave this case without saving your notes.'
                  : 'Your edits to status, owner, or notes have not been saved.'}
              </p>
              <div className="discard-actions">
                <button className="btn-action" autoFocus onClick={cancelDiscard}>
                  Keep editing
                </button>
                <button className="btn-action danger" onClick={confirmDiscard}>
                  Discard
                </button>
              </div>
            </div>
          </div>
        )}
      </aside>
    </div>
  );
}
