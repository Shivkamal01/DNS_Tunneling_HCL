import React, { useCallback, useEffect, useRef, useState } from 'react';
import { XIcon, RefreshIcon, TerminalIcon } from './Icons';
import { api, describeError } from '../services/api';

const POLL_INTERVAL = 5000;
const SEVERITY_COLORS = {
  CRITICAL: '#d3564f',
  HIGH:     '#cf8748',
  MEDIUM:   '#6b8fb5',
  LOW:      '#7fa583',
};

export function TelemetryStreamModal({ isOpen, onClose }) {
  const [queries, setQueries] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [isLive, setIsLive] = useState(true);
  const isMounted = useRef(true);

  useEffect(() => {
    isMounted.current = true;
    return () => { isMounted.current = false; };
  }, []);

  const fetchQueries = useCallback(async (quiet = false) => {
    if (!quiet) setIsLoading(true);
    try {
      const payload = await api.getQueries(80);
      if (!isMounted.current) return;
      setQueries(payload.data || []);
      setError(null);
    } catch (err) {
      if (!isMounted.current) return;
      setError(describeError(err));
    } finally {
      if (isMounted.current) setIsLoading(false);
    }
  }, []);

  /**
   * Poll while the panel is open. The previous version fetched exactly once on
   * mount, so a stream labelled "live" never showed a new packet without the
   * user reopening the modal.
   */
  useEffect(() => {
    if (!isOpen) return undefined;

    fetchQueries();

    if (!isLive) return undefined;
    const timer = setInterval(() => fetchQueries(true), POLL_INTERVAL);
    return () => clearInterval(timer);
  }, [isOpen, isLive, fetchQueries]);

  // Escape closes the modal.
  useEffect(() => {
    if (!isOpen) return undefined;
    const handler = (event) => { if (event.key === 'Escape') onClose(); };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div
        className="modal-container telemetry-modal-wide"
        onClick={(event) => event.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label="Raw DNS telemetry stream"
      >
        <div className="modal-header">
          <div className="modal-title-wrap">
            <TerminalIcon size={15} color="var(--accent)" />
            <h3>Raw DNS telemetry</h3>
          </div>

          <div className="modal-header-actions">
            <button
              className={`btn-action ${isLive ? 'primary' : ''}`}
              onClick={() => setIsLive((live) => !live)}
              title={isLive ? 'Pause auto-refresh' : 'Resume auto-refresh'}
            >
              {isLive ? 'Live · 5s' : 'Paused'}
            </button>
            <button className="btn-action" onClick={() => fetchQueries()} disabled={isLoading}>
              <RefreshIcon size={12} className={isLoading ? 'spin-anim' : ''} />
              <span>Refresh</span>
            </button>
            <button className="modal-close-btn" onClick={onClose} aria-label="Close telemetry stream">
              <XIcon size={16} />
            </button>
          </div>
        </div>

        <div className="modal-body">
          <p className="modal-description">
            Most recent DNS queries in the pipeline. Every row has been scored; rows with a
            verdict above Benign also produced an alert.
          </p>

          {error && <div className="sim-result-banner error">{error}</div>}

          <div className="telemetry-table-wrapper">
            <table className="telemetry-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Source</th>
                  <th>Type</th>
                  <th>Queried domain</th>
                  <th>H(X)</th>
                  <th>Sub len</th>
                  <th>Encoding</th>
                  <th>Verdict</th>
                </tr>
              </thead>
              <tbody>
                {isLoading && queries.length === 0 ? (
                  <tr>
                    <td colSpan="8" className="telemetry-empty">Loading query stream…</td>
                  </tr>
                ) : queries.length === 0 ? (
                  <tr>
                    <td colSpan="8" className="telemetry-empty">
                      No telemetry yet — ingest a log or run a simulation first.
                    </td>
                  </tr>
                ) : (
                  queries.map((query) => {
                    const entropy = typeof query.entropy === 'number' ? query.entropy.toFixed(2) : '—';
                    const severity = (query.severity || '').toUpperCase();
                    const isThreat = Boolean(query.risk_score && query.risk_score > 0);

                    return (
                      <tr key={query.id} className={isThreat ? 'threat-row' : ''}>
                        <td className="mono text-muted">
                          {query.timestamp
                            ? new Date(query.timestamp).toLocaleTimeString('en-GB', { hour12: false })
                            : '—'}
                        </td>
                        <td className="mono">{query.source_ip}</td>
                        <td>
                          <span className="record-type-tag">{query.qtype_name || 'A'}</span>
                        </td>
                        <td className="mono domain-stream-cell" title={query.domain}>
                          {query.domain}
                        </td>
                        <td className={`mono ${entropy !== '—' && parseFloat(entropy) >= 3.75 ? 'entropy-high' : ''}`}>
                          {entropy}
                        </td>
                        <td className="mono">{query.subdomain_length ?? 0}</td>
                        <td>
                          <span className="whitelist-source">{query.encoding || 'ascii'}</span>
                        </td>
                        <td>
                          {query.is_whitelisted ? (
                            <span className="verdict-badge benign">Whitelisted</span>
                          ) : isThreat ? (
                            <span
                              className={`verdict-badge ${severity.toLowerCase()}`}
                              style={{ color: SEVERITY_COLORS[severity] }}
                            >
                              {severity} {query.risk_score}
                            </span>
                          ) : (
                            <span className="verdict-badge benign">Benign</span>
                          )}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
