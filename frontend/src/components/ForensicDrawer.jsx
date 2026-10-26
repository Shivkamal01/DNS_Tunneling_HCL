import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  XIcon, CopyIcon, ExternalLinkIcon, CheckCircleIcon,
  ShieldIcon, DatabaseIcon, TerminalIcon, ClockIcon,
} from './Icons';
import {
  formatBytes,
  formatDateTime,
  ipContext,
  payloadSampleLength,
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

const SEVERITY_COLORS = {
  CRITICAL: '#d3564f',
  HIGH:     '#cf8748',
  MEDIUM:   '#6b8fb5',
  LOW:      '#7fa583',
};

const INCIDENT_STATUS_COLORS = {
  OPEN:             { color: '#d3564f', bg: 'rgba(211,86,79,0.12)' },
  INVESTIGATING:    { color: '#cf8748', bg: 'rgba(207,135,72,0.12)' },
  CONTAINED:        { color: '#6b8fb5', bg: 'rgba(107,143,181,0.12)' },
  RESOLVED:         { color: '#7fa583', bg: 'rgba(127,165,131,0.12)' },
  'FALSE POSITIVE': { color: '#6b6b76', bg: 'rgba(107,107,118,0.12)' },
  CLOSED:           { color: '#6b6b76', bg: 'rgba(107,107,118,0.12)' },
};

const formatRatio = (value) =>
  typeof value === 'number' ? `${(value * 100).toFixed(0)}%` : '—';

/**
 * Attempt to recover plaintext from an encoded subdomain label.
 *
 * The previous version stripped every non-hex character and decoded whatever
 * remained, so "www" or "deadbeef" inside an ordinary hostname produced
 * confident-looking garbage. Three guards now apply: the candidate has to make
 * up most of the label, it has to be a plausible length, and the decoded bytes
 * have to be mostly printable.
 */
function tryDecodePayload(domain) {
  if (!domain) return null;

  const parts = domain.split('.');
  if (parts.length <= 2) return null;

  const subdomain = parts.slice(0, -2).join('.');
  const candidate = subdomain.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
  const compact = subdomain.replace(/[^a-zA-Z0-9]/g, '');

  // The hex candidate must dominate the label, not be a couple of stray
  // letters picked out of a normal word.
  if (!compact || candidate.length / compact.length < 0.75) return null;
  if (candidate.length < 16 || candidate.length % 2 !== 0) return null;

  let decoded = '';
  let printable = 0;
  for (let i = 0; i < candidate.length; i += 2) {
    const code = parseInt(candidate.slice(i, i + 2), 16);
    if (Number.isNaN(code)) return null;
    if (code >= 32 && code <= 126) {
      decoded += String.fromCharCode(code);
      printable += 1;
    } else {
      decoded += '·';
    }
  }

  const total = candidate.length / 2;
  const printableRatio = printable / total;

  if (printableRatio < 0.6) {
    return {
      type: 'Hex (binary)',
      decoded: `${candidate.slice(0, 48)}${candidate.length > 48 ? '…' : ''}`,
      printableRatio,
      note: `Decodes to ${Math.round(printableRatio * 100)}% printable bytes — likely encrypted or compressed.`,
    };
  }

  return {
    type: 'Hex / ASCII',
    decoded,
    printableRatio,
    note: 'Reconstructed plaintext from the hex-encoded label stream.',
  };
}

export function ForensicDrawer({
  alert,
  onClose,
  onUpdateStatus,
  onCopyText,
}) {
  const drawerRef = useRef(null);
  const discardRef = useRef(null);
  const loadedIdRef = useRef(null);
  const [currentStatus, setCurrentStatus] = useState('OPEN');
  const [notes, setNotes] = useState('');
  const [baseline, setBaseline] = useState({ status: 'OPEN', notes: '' });
  const [isSaving, setIsSaving] = useState(false);
  const [confirmDiscard, setConfirmDiscard] = useState(false);

  // The drawer opens from a table/telemetry summary and is then replaced by the
  // full alert payload. Keep the latest form values in a ref so that late detail
  // can fill in status/notes without erasing fields the analyst already edited.
  const formRef = useRef({ currentStatus, notes, baseline });
  formRef.current = { currentStatus, notes, baseline };

  useBodyScrollLock(Boolean(alert));
  useFocusReturn(Boolean(alert), drawerRef);
  useFocusTrap(Boolean(alert), drawerRef);
  useFocusTrap(Boolean(confirmDiscard), discardRef);

  useEffect(() => {
    if (!alert) {
      loadedIdRef.current = null;
      return;
    }

    const safeStatus = (alert.status || 'OPEN').toUpperCase();
    const safeNotes = alert.analyst_notes || '';

    // The same alert can arrive twice: once as the row summary and again as the
    // full detail response. Only preserve fields that actually differ from the
    // current baseline; untouched fields should adopt the server values.
    if (loadedIdRef.current === alert.id) {
      const form = formRef.current;
      const statusTouched = form.currentStatus !== form.baseline.status;
      const notesTouched = form.notes !== form.baseline.notes;

      setBaseline({ status: safeStatus, notes: safeNotes });
      if (!statusTouched) setCurrentStatus(safeStatus);
      if (!notesTouched) setNotes(safeNotes);
      return;
    }

    loadedIdRef.current = alert.id;
    setCurrentStatus(safeStatus);
    setNotes(safeNotes);
    setBaseline({ status: safeStatus, notes: safeNotes });
    setConfirmDiscard(false);
  }, [alert]);

  const dirty = Boolean(alert) && (
    currentStatus !== baseline.status || notes !== baseline.notes
  );
  const statusKnown = Boolean(alert?.status);

  const requestClose = useCallback(() => {
    if (dirty) {
      setConfirmDiscard(true);
      return;
    }
    onClose();
  }, [dirty, onClose]);

  const cancelDiscard = () => {
    setConfirmDiscard(false);
    drawerRef.current?.querySelector('.drawer-close-btn')?.focus();
  };

  useEscapeKey(Boolean(alert), () => {
    if (confirmDiscard) {
      cancelDiscard();
      return;
    }
    requestClose();
  });

  const decodedResult = useMemo(() => tryDecodePayload(alert?.domain), [alert?.domain]);
  const network = useMemo(() => ipContext(alert?.source_ip), [alert?.source_ip]);
  // Recompute on every render so the response clock visibly counts down while
  // the drawer stays open instead of freezing at open time.
  const sla = slaFor(alert?.severity, alert?.created_at, Date.now(), alert?.status);

  if (!alert) return null;

  const sevColor = SEVERITY_COLORS[(alert.severity || 'LOW').toUpperCase()] || '#6b8fb5';
  const entropyVal = typeof alert.entropy === 'number' ? alert.entropy : 0;

  const queryLen = alert.query_length || alert.domain?.length || 8;

  // Match utils.normalized_entropy(): the ceiling is based on the stripped
  // payload (subdomain when present), not the whole QNAME. Using the full
  // query length here made the displayed ceiling disagree with the stored
  // entropy ratio.
  const payloadLen = payloadSampleLength(alert.domain);

  // Entropy is length-dependent, so the meter shows the normalised ratio
  // (0–1) rather than the raw bits-per-character value. The ceiling is
  // log2(min(payload_len, 37)): 37 is the length at which a uniform 37-symbol
  // payload reaches the ~5.21-bit practical maximum used by the scoring engine.
  const entropyCeiling = payloadLen >= 2 ? Math.log2(Math.min(payloadLen, 37)) : 0;
  const entropyRatio = typeof alert.entropy_ratio === 'number'
    ? alert.entropy_ratio
    : (entropyCeiling > 0 ? Math.min(entropyVal / entropyCeiling, 1) : 0);
  const entropyPct = Math.min(Math.max(entropyRatio * 100, 0), 100);
  const THRESHOLD_RATIO = 0.8;

  const statusKey = currentStatus.toUpperCase();
  const linkedIncidents = Array.isArray(alert.incidents) ? alert.incidents : [];

  const handleSaveNotes = async () => {
    if (!dirty || isSaving || !statusKnown) return;

    setIsSaving(true);
    try {
      const saved = await onUpdateStatus(alert.id, currentStatus, notes);
      if (saved !== false) {
        setBaseline({ status: currentStatus, notes });
      }
    } finally {
      setIsSaving(false);
    }
  };

  const resetFields = () => {
    setCurrentStatus(baseline.status);
    setNotes(baseline.notes);
  };

  const handleCopy = (value, message) => {
    if (onCopyText) onCopyText(value, message);
  };

  return (
    <div className="drawer-backdrop" onClick={requestClose}>
      <aside
        className="forensic-drawer"
        ref={drawerRef}
        tabIndex={-1}
        onClick={(event) => event.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-labelledby="forensic-drawer-title"
      >
        <div className="drawer-header">
          <div className="drawer-header-left">
            <span className="drawer-tag mono">ALERT #{String(alert.id).padStart(4, '0')}</span>
            <span
              className="badge-severity"
              style={{ borderColor: `${sevColor}44`, color: sevColor, background: `${sevColor}14` }}
            >
              <span className="sev-dot" style={{ background: sevColor }} />
              {alert.severity} SEVERITY
            </span>
            <span className={`sla-chip ${sla.state}`} title={sla.dueAt ? `Due ${formatDateTime(sla.dueAt)}` : undefined}>
              <ClockIcon size={10} />
              {sla.label}
            </span>
          </div>

          <button className="drawer-close-btn" onClick={requestClose} aria-label="Close alert detail">
            <XIcon size={18} />
          </button>
        </div>

        <div className="drawer-body">
          <section className="forensic-section">
            <div className="target-summary-card">
              <div className="target-domain-row">
                <span className="record-badge">{alert.qtype_name || 'A'}</span>
                <span id="forensic-drawer-title" className="target-domain-text mono">{alert.domain}</span>
                <button
                  className="btn-copy-inline"
                  onClick={() => handleCopy(alert.domain, 'Domain copied')}
                  title="Copy domain to clipboard"
                >
                  <CopyIcon size={13} />
                </button>
              </div>

              <div className="target-meta-grid">
                <div className="meta-item">
                  <span className="meta-label">Source client IP</span>
                  <div className="meta-val-row">
                    <span className="mono">{alert.source_ip}</span>
                    <button
                      className="btn-copy-inline"
                      onClick={() => handleCopy(alert.source_ip, 'IP address copied')}
                      title="Copy IP"
                    >
                      <CopyIcon size={12} />
                    </button>
                  </div>
                  <span className="meta-note">{network.label}{network.subnet !== '—' ? ` · ${network.subnet}` : ''}</span>
                </div>

                <div className="meta-item">
                  <span className="meta-label">Calculated risk score</span>
                  <span className="meta-val mono" style={{ color: sevColor, fontWeight: 700 }}>
                    {alert.risk_score} / 100
                  </span>
                  <span className="meta-note">Weighted indicator total, capped at 100</span>
                </div>

                <div className="meta-item">
                  <span className="meta-label">Est. exfiltrated bytes</span>
                  <span className="meta-val mono">
                    {typeof alert.est_payload_bytes === 'number'
                      ? formatBytes(alert.est_payload_bytes)
                      : '—'}
                  </span>
                  <span className="meta-note">Decoded payload estimate</span>
                </div>

                <div className="meta-item">
                  <span className="meta-label">Query length</span>
                  <span className="meta-val mono">{queryLen} chars</span>
                  <span className="meta-note">
                    {alert.subdomain_length ? `${alert.subdomain_length} in subdomain` : 'Full QNAME'}
                  </span>
                </div>

                <div className="meta-item">
                  <span className="meta-label">Detected</span>
                  <span className="meta-val mono">{formatDateTime(alert.created_at)}</span>
                  <span className="meta-note">{timeAgo(alert.created_at)}</span>
                </div>

                <div className="meta-item">
                  <span className="meta-label">Query observed</span>
                  <span className="meta-val mono">
                    {alert.query_time ? formatDateTime(alert.query_time) : formatDateTime(alert.created_at)}
                  </span>
                  <span className="meta-note">Sensor timestamp</span>
                </div>
              </div>
            </div>
          </section>

          <section className="forensic-section">
            <div className={`sla-banner ${sla.state}`}>
              <ClockIcon size={16} />
              <div className="sla-copy">
                <span className="sla-title">Triage SLA · {sla.hours}h for {sla.level}</span>
                <strong>{sla.label}</strong>
                <span className="sla-due">
                  {sla.state === 'closed'
                    ? 'Response clock stopped'
                    : sla.dueAt ? `Due ${formatDateTime(sla.dueAt)}` : 'No detection timestamp'}
                </span>
              </div>
            </div>
          </section>

          <section className="forensic-section">
            <div className="section-title">
              <ShieldIcon size={15} color="#d9a04a" />
              <h4>Mathematical &amp; statistical profiling</h4>
            </div>

            <div className="entropy-analyzer-card">
              <div className="entropy-label-row">
                <span className="entropy-title">Shannon entropy H(X)</span>
                <span className="entropy-val mono" style={{ color: entropyRatio >= THRESHOLD_RATIO ? '#cf8748' : '#e8e8ea' }}>
                  {entropyVal.toFixed(3)}
                </span>
              </div>

              <div className="entropy-meter-track">
                <div
                  className="entropy-meter-fill"
                  style={{
                    width: `${entropyPct}%`,
                    background: entropyRatio >= THRESHOLD_RATIO
                      ? 'linear-gradient(90deg, #6b8fb5, #cf8748)'
                      : '#6b8fb5',
                  }}
                />
                <div
                  className="entropy-threshold-mark"
                  style={{ left: `${THRESHOLD_RATIO * 100}%` }}
                  title={`Threshold: ${THRESHOLD_RATIO} of ceiling`}
                />
              </div>

              <div className="entropy-meta-row">
                <span>0.0 (Natural language)</span>
                <span className="threshold-tag">
                  {Math.round(entropyRatio * 100)}% of ceiling
                </span>
                <span>1.0 (Random)</span>
              </div>

              <div className="entropy-footnote mono">
                ceiling = log2(min({payloadLen}, 37)) = {entropyCeiling.toFixed(2)} bits
              </div>
            </div>

            <div className="feature-stat-grid">
              <div className="feature-stat-box">
                <span className="feat-label">Hex ratio</span>
                <span className="feat-val mono">{formatRatio(alert.hex_ratio)}</span>
              </div>
              <div className="feature-stat-box">
                <span className="feat-label">Base32 charset</span>
                <span className="feat-val mono">
                  {typeof alert.base32_foreign_ratio === 'number'
                    ? formatRatio(1 - alert.base32_foreign_ratio)
                    : '—'}
                </span>
              </div>
              <div className="feature-stat-box">
                <span className="feat-label">Vowel ratio</span>
                <span className="feat-val mono">{formatRatio(alert.vowel_ratio)}</span>
              </div>
              <div className="feature-stat-box">
                <span className="feat-label">Subdomain len</span>
                <span className="feat-val mono">{alert.subdomain_length || 0}</span>
              </div>
            </div>
          </section>

          {decodedResult && (
            <section className="forensic-section">
              <div className="section-title">
                <TerminalIcon size={15} color="#7fa583" />
                <h4>Payload extraction &amp; decode attempt</h4>
              </div>

              <div className="decoded-payload-box">
                <div className="decode-tag">{decodedResult.type}</div>
                <div className="decoded-text mono">{decodedResult.decoded}</div>
                <span className="decode-hint">{decodedResult.note}</span>
              </div>
            </section>
          )}

          <section className="forensic-section">
            <div className="section-title">
              <DatabaseIcon size={15} color="#cf8748" />
              <h4>Triggered threat indicators</h4>
            </div>

            <div className="indicators-list">
              {(alert.indicator_list && alert.indicator_list.length > 0) ? (
                alert.indicator_list.map((indicator, index) => (
                  <div key={`${indicator}-${index}`} className="indicator-pill">
                    <span className="indicator-bullet">•</span>
                    <span>{indicator}</span>
                  </div>
                ))
              ) : (
                <div className="indicator-pill">
                  <span className="indicator-bullet">•</span>
                  <span>{alert.detection_reason || 'Anomalous DNS traffic pattern'}</span>
                </div>
              )}
            </div>
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
              Mapping describes the observed DNS behaviour. It is not evidence of
              a specific tool or actor on its own.
            </p>
          </section>

          {linkedIncidents.length > 0 && (
            <section className="forensic-section">
              <div className="section-title">
                <DatabaseIcon size={15} color="#94a3b8" />
                <h4>Linked incidents</h4>
              </div>

              <div className="linked-incident-list">
                {linkedIncidents.map((incident) => {
                  const status = (incident.status || 'OPEN').toUpperCase();
                  const colors = INCIDENT_STATUS_COLORS[status] || INCIDENT_STATUS_COLORS.OPEN;

                  return (
                    <div className="linked-incident-row" key={incident.id}>
                      <span className="linked-incident-id mono">
                        INC-{String(incident.id).padStart(4, '0')}
                      </span>
                      <span
                        className="linked-incident-status"
                        style={{ color: colors.color, background: colors.bg, borderColor: `${colors.color}44` }}
                      >
                        {status}
                      </span>
                      <span className="linked-incident-owner">
                        {incident.assigned_to || 'Unassigned'}
                      </span>
                      <span className="linked-incident-time mono">
                        {formatDateTime(incident.created_at)}
                      </span>
                    </div>
                  );
                })}
              </div>
            </section>
          )}

          <section className="forensic-section">
            <div className="section-title">
              <ExternalLinkIcon size={15} color="#94a3b8" />
              <h4>External threat intelligence</h4>
            </div>

            <div className="pivot-actions-grid">
              <a
                className="btn-pivot"
                href={`https://www.virustotal.com/gui/domain/${encodeURIComponent(alert.domain)}`}
                target="_blank"
                rel="noopener noreferrer"
              >
                <span>VirusTotal</span>
                <ExternalLinkIcon size={12} />
              </a>

              <a
                className="btn-pivot"
                href={`https://www.shodan.io/search?query=${encodeURIComponent(alert.source_ip)}`}
                target="_blank"
                rel="noopener noreferrer"
              >
                <span>Shodan Host</span>
                <ExternalLinkIcon size={12} />
              </a>

              <a
                className="btn-pivot"
                href={`https://www.abuseipdb.com/check/${encodeURIComponent(alert.source_ip)}`}
                target="_blank"
                rel="noopener noreferrer"
              >
                <span>AbuseIPDB</span>
                <ExternalLinkIcon size={12} />
              </a>
            </div>
            <p className="fine-print">
              Pivot links query third parties and may disclose the indicator.
            </p>
          </section>

          <section className="forensic-section triage-section">
            <div className="section-title">
              <CheckCircleIcon size={15} color="#d9a04a" />
              <h4>Incident response &amp; triage</h4>
              {dirty && <span className="unsaved-pill">Unsaved</span>}
            </div>

            <div className="triage-controls">
              <div className="control-group">
                <label className="control-label" htmlFor="alert-triage-status">Alert triage status</label>
                <select
                  id="alert-triage-status"
                  className="triage-status-select"
                  value={statusKey}
                  onChange={(event) => setCurrentStatus(event.target.value)}
                  disabled={!statusKnown || isSaving}
                >
                  <option value="OPEN">Open (requires triage)</option>
                  <option value="INVESTIGATING">Investigating (analyst assigned)</option>
                  <option value="CONTAINED">Contained (firewall / EDR isolation active)</option>
                  <option value="RESOLVED">Resolved (remediation complete)</option>
                  <option value="FALSE POSITIVE">False positive (benign traffic verified)</option>
                </select>
              </div>

              <div className="control-group">
                <div className="control-label-row">
                  <label className="control-label" htmlFor="alert-triage-notes">Alert triage notes</label>
                  <span className="char-count">{notes.length}/4000</span>
                </div>
                <textarea
                  id="alert-triage-notes"
                  className="triage-notes-area"
                  rows={4}
                  maxLength={4000}
                  placeholder="Record forensic observations, firewall rules applied, or EDR containment actions…"
                  value={notes}
                  onChange={(event) => setNotes(event.target.value)}
                  disabled={!statusKnown || isSaving}
                  onKeyDown={(event) => {
                    if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
                      event.preventDefault();
                      handleSaveNotes();
                    }
                  }}
                />
                <span className="control-hint">Ctrl+Enter saves. Status syncs to the linked case; closed cases are not reopened. Notes stay with the alert.</span>
                {!statusKnown && (
                  <span className="control-hint">
                    Waiting for the persisted status before triage controls unlock.
                  </span>
                )}
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
              onClick={handleSaveNotes}
              disabled={!dirty || isSaving || !statusKnown}
            >
              {isSaving ? 'Saving…' : 'Save triage'}
            </button>
          </div>
        </div>

        {confirmDiscard && (
          <div className="discard-overlay" role="alertdialog" aria-modal="true" aria-labelledby="alert-discard-title">
            <div className="discard-card" ref={discardRef} tabIndex={-1}>
              <h5 id="alert-discard-title">Discard unsaved triage?</h5>
              <p>Your status or notes edits have not been saved to this alert.</p>
              <div className="discard-actions">
                <button className="btn-action" autoFocus onClick={cancelDiscard}>
                  Keep editing
                </button>
                <button className="btn-action danger" onClick={onClose}>
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
