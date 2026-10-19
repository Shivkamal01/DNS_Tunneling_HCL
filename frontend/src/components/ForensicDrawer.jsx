import React, { useState, useEffect } from 'react';
import {
  XIcon, CopyIcon, ExternalLinkIcon, CheckCircleIcon,
  ShieldIcon, DatabaseIcon, TerminalIcon
} from './Icons';

const SEVERITY_COLORS = {
  CRITICAL: '#d3564f',
  HIGH:     '#cf8748',
  MEDIUM:   '#6b8fb5',
  LOW:      '#7fa583',
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
  const [currentStatus, setCurrentStatus] = useState(alert?.status || 'OPEN');
  const [notes, setNotes] = useState(alert?.analyst_notes || '');
  const [isSaving, setIsSaving] = useState(false);

  useEffect(() => {
    if (alert) {
      setCurrentStatus(alert.status || 'OPEN');
      setNotes(alert.analyst_notes || '');
    }
  }, [alert]);

  // Esc key listener
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  if (!alert) return null;

  const sevColor = SEVERITY_COLORS[(alert.severity || 'LOW').toUpperCase()] || '#6b8fb5';
  const decodedResult = tryDecodePayload(alert.domain);
  const entropyVal = typeof alert.entropy === 'number' ? alert.entropy : 0.0;
  // Entropy is length-dependent, so the meter shows the length-normalised
  // ratio (0-1) rather than the raw bits-per-character value.
  const entropyRatio = typeof alert.entropy_ratio === 'number'
    ? alert.entropy_ratio
    : Math.min(entropyVal / 4.8, 1);
  const entropyPct = Math.min(Math.max(entropyRatio * 100, 0), 100);
  const THRESHOLD_RATIO = 0.8;

  const handleSaveNotes = async () => {
    setIsSaving(true);
    try {
      await onUpdateStatus(alert.id, currentStatus, notes);
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="drawer-backdrop" onClick={onClose}>
      <aside className="forensic-drawer" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
        {/* Drawer Header */}
        <div className="drawer-header">
          <div className="drawer-header-left">
            <span className="drawer-tag mono">ALERT #{String(alert.id).padStart(4, '0')}</span>
            <span className="badge-severity" style={{ borderColor: `${sevColor}44`, color: sevColor, background: `${sevColor}14` }}>
              <span className="sev-dot" style={{ background: sevColor }} />
              {alert.severity} SEVERITY
            </span>
          </div>

          <button className="drawer-close-btn" onClick={onClose} aria-label="Close drawer">
            <XIcon size={18} />
          </button>
        </div>

        {/* Drawer Body Scroll */}
        <div className="drawer-body">
          {/* Section 1: Target Summary Card */}
          <div className="forensic-section">
            <div className="target-summary-card">
              <div className="target-domain-row">
                <span className="record-badge">{alert.qtype_name || 'A'}</span>
                <span className="target-domain-text mono">{alert.domain}</span>
                <button
                  className="btn-copy-inline"
                  onClick={() => onCopyText(alert.domain, 'Domain copied')}
                  title="Copy domain to clipboard"
                >
                  <CopyIcon size={13} />
                </button>
              </div>

              <div className="target-meta-grid">
                <div className="meta-item">
                  <span className="meta-label">Source Client IP</span>
                  <div className="meta-val-row">
                    <span className="mono">{alert.source_ip}</span>
                    <button
                      className="btn-copy-inline"
                      onClick={() => onCopyText(alert.source_ip, 'IP address copied')}
                      title="Copy IP"
                    >
                      <CopyIcon size={12} />
                    </button>
                  </div>
                </div>

                <div className="meta-item">
                  <span className="meta-label">Calculated Risk Score</span>
                  <span className="meta-val mono" style={{ color: sevColor, fontWeight: 700 }}>
                    {alert.risk_score} / 100
                  </span>
                </div>

                <div className="meta-item">
                  <span className="meta-label">Est. Exfiltrated Bytes</span>
                  <span className="meta-val mono">
                    {alert.est_payload_bytes ? `${alert.est_payload_bytes} B` : '—'}
                  </span>
                </div>

                <div className="meta-item">
                  <span className="meta-label">Query Length</span>
                  <span className="meta-val mono">
                    {alert.query_length || alert.domain?.length || 0} chars
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Section 2: Mathematical Entropy & Lexical Forensics */}
          <div className="forensic-section">
            <div className="section-title">
              <ShieldIcon size={15} color="#d9a04a" />
              <h4>Mathematical &amp; Statistical Profiling</h4>
            </div>

            {/* Shannon Entropy Visualizer */}
            <div className="entropy-analyzer-card">
              <div className="entropy-label-row">
                <span className="entropy-title">Shannon Entropy H(X)</span>
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
            </div>

            {/* Character Distribution Grid */}
            <div className="feature-stat-grid">
              <div className="feature-stat-box">
                <span className="feat-label">Hex Ratio</span>
                <span className="feat-val mono">{formatRatio(alert.hex_ratio)}</span>
              </div>
              <div className="feature-stat-box">
                <span className="feat-label">Base32 Safe</span>
                <span className="feat-val mono">
                  {alert.base32_foreign_ratio !== undefined
                    ? formatRatio(1 - alert.base32_foreign_ratio)
                    : '—'}
                </span>
              </div>
              <div className="feature-stat-box">
                <span className="feat-label">Vowel Ratio</span>
                <span className="feat-val mono">{formatRatio(alert.vowel_ratio)}</span>
              </div>
              <div className="feature-stat-box">
                <span className="feat-label">Subdomain Len</span>
                <span className="feat-val mono">{alert.subdomain_length || 0}</span>
              </div>
            </div>
          </div>

          {/* Section 3: Subdomain Payload Decoder */}
          {decodedResult && (
            <div className="forensic-section">
              <div className="section-title">
                <TerminalIcon size={15} color="#7fa583" />
                <h4>Payload Extraction &amp; Decode Attempt</h4>
              </div>

              <div className="decoded-payload-box">
                <div className="decode-tag">{decodedResult.type}</div>
                <div className="decoded-text mono">{decodedResult.decoded}</div>
                <span className="decode-hint">{decodedResult.note}</span>
              </div>
            </div>
          )}

          {/* Section 4: Triggered Heuristic Indicators */}
          <div className="forensic-section">
            <div className="section-title">
              <DatabaseIcon size={15} color="#cf8748" />
              <h4>Triggered Threat Indicators</h4>
            </div>

            <div className="indicators-list">
              {(alert.indicator_list && alert.indicator_list.length > 0) ? (
                alert.indicator_list.map((ind, i) => (
                  <div key={i} className="indicator-pill">
                    <span className="indicator-bullet">•</span>
                    <span>{ind}</span>
                  </div>
                ))
              ) : (
                <div className="indicator-pill">
                  <span className="indicator-bullet">•</span>
                  <span>{alert.detection_reason || 'Anomalous DNS traffic pattern'}</span>
                </div>
              )}
            </div>
          </div>

          {/* Section 5: Threat Intelligence Pivots */}
          <div className="forensic-section">
            <div className="section-title">
              <ExternalLinkIcon size={15} color="#94a3b8" />
              <h4>External Threat Intelligence</h4>
            </div>

            <div className="pivot-actions-grid">
              <a
                className="btn-pivot"
                href={`https://www.virustotal.com/gui/domain/${alert.domain}`}
                target="_blank"
                rel="noopener noreferrer"
              >
                <span>VirusTotal</span>
                <ExternalLinkIcon size={12} />
              </a>

              <a
                className="btn-pivot"
                href={`https://www.shodan.io/search?query=${alert.source_ip}`}
                target="_blank"
                rel="noopener noreferrer"
              >
                <span>Shodan Host</span>
                <ExternalLinkIcon size={12} />
              </a>

              <a
                className="btn-pivot"
                href={`https://www.abuseipdb.com/check/${alert.source_ip}`}
                target="_blank"
                rel="noopener noreferrer"
              >
                <span>AbuseIPDB</span>
                <ExternalLinkIcon size={12} />
              </a>
            </div>
          </div>

          {/* Section 6: Analyst Triage & Notes */}
          <div className="forensic-section triage-section">
            <div className="section-title">
              <CheckCircleIcon size={15} color="#d9a04a" />
              <h4>Incident Response &amp; Triage</h4>
            </div>

            <div className="triage-controls">
              <div className="control-group">
                <label className="control-label">Incident Lifecycle State</label>
                <select
                  className="triage-status-select"
                  value={currentStatus}
                  onChange={(e) => setCurrentStatus(e.target.value)}
                >
                  <option value="OPEN">Open (Requires Triage)</option>
                  <option value="INVESTIGATING">Investigating (SOC Analyst Assigned)</option>
                  <option value="CONTAINED">Contained (Firewall/EDR Isolation Active)</option>
                  <option value="RESOLVED">Resolved (Remediation Complete)</option>
                  <option value="FALSE POSITIVE">False Positive (Benign Traffic Verified)</option>
                </select>
              </div>

              <div className="control-group">
                <label className="control-label">Analyst Case Notes</label>
                <textarea
                  className="triage-notes-area"
                  rows={4}
                  placeholder="Record forensic observations, firewall rules applied, or EDR containment actions…"
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                />
              </div>

              <button
                className="btn-save-triage primary"
                onClick={handleSaveNotes}
                disabled={isSaving}
              >
                {isSaving ? 'Committing Changes…' : 'Save Triage Status & Notes'}
              </button>
            </div>
          </div>
        </div>
      </aside>
    </div>
  );
}
