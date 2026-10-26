import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { XIcon, RefreshIcon, TerminalIcon, ChevronRightIcon } from './Icons';
import { api, describeError } from '../services/api';
import { formatClock, formatDateTime, payloadSampleLength } from '../utils/format';
import {
  useBodyScrollLock,
  useEscapeKey,
  useFocusReturn,
  useFocusTrap,
} from '../utils/overlay';

const POLL_INTERVAL = 5000;
const SEVERITY_COLORS = {
  CRITICAL: '#d3564f',
  HIGH:     '#cf8748',
  MEDIUM:   '#6b8fb5',
  LOW:      '#7fa583',
};

export function TelemetryStreamModal({ isOpen, onClose, onOpenAlert }) {
  const [queries, setQueries] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [isLive, setIsLive] = useState(true);
  const [onlyThreats, setOnlyThreats] = useState(false);
  const [updatedAt, setUpdatedAt] = useState(null);
  const isMounted = useRef(true);
  const modalRef = useRef(null);
  const requestRef = useRef(0);

  useBodyScrollLock(isOpen);
  useFocusReturn(isOpen, modalRef);
  useFocusTrap(isOpen, modalRef);
  useEscapeKey(isOpen, onClose);

  useEffect(() => {
    isMounted.current = true;
    return () => { isMounted.current = false; };
  }, []);

  const fetchQueries = useCallback(async (quiet = false) => {
    const requestId = ++requestRef.current;
    if (!quiet) setIsLoading(true);
    try {
      const payload = await api.getQueries(80);
      if (!isMounted.current || requestId !== requestRef.current) return;
      setQueries(payload.data || []);
      setUpdatedAt(new Date());
      setError(null);
    } catch (err) {
      if (!isMounted.current || requestId !== requestRef.current) return;
      setError(describeError(err));
    } finally {
      if (isMounted.current && requestId === requestRef.current) setIsLoading(false);
    }
  }, []);

  // Poll while the panel is open. A stream labelled "live" should keep
  // producing new rows without the operator reopening the modal.
  useEffect(() => {
    if (!isOpen) return undefined;

    fetchQueries();

    if (!isLive) return undefined;
    const timer = setInterval(() => fetchQueries(true), POLL_INTERVAL);
    return () => clearInterval(timer);
  }, [isOpen, isLive, fetchQueries]);

  const alertCount = useMemo(
    () => queries.filter((query) => Boolean(query.alert_id)).length,
    [queries],
  );

  const visibleQueries = useMemo(() => (
    onlyThreats
      ? queries.filter((query) => Boolean(query.alert_id) || (query.risk_score > 0 && !query.is_whitelisted))
      : queries
  ), [queries, onlyThreats]);

  if (!isOpen) return null;

  const openAlert = (alertId) => {
    if (!alertId || !onOpenAlert) return;
    onOpenAlert(alertId);
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div
        className="modal-container telemetry-modal-wide"
        ref={modalRef}
        tabIndex={-1}
        onClick={(event) => event.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label="Raw DNS telemetry stream"
      >
        <div className="modal-header">
          <div className="modal-title-wrap">
            <TerminalIcon size={15} color="var(--accent)" />
            <div>
              <h3>Raw DNS telemetry</h3>
              <span className="modal-subtitle">
                {queries.length} recent queries · {alertCount} alerts
                {updatedAt ? ` · updated ${formatClock(updatedAt)} UTC` : ''}
              </span>
            </div>
          </div>

          <div className="modal-header-actions">
            <button
              className={`btn-action ${onlyThreats ? 'active' : ''}`}
              onClick={() => setOnlyThreats((value) => !value)}
              title="Show only rows that produced an alert"
              aria-pressed={onlyThreats}
            >
              {onlyThreats ? 'All traffic' : `Threats only (${alertCount})`}
            </button>
            <button
              className={`btn-action ${isLive ? 'primary' : ''}`}
              onClick={() => setIsLive((live) => !live)}
              title={isLive ? 'Pause auto-refresh' : 'Resume auto-refresh'}
              aria-pressed={isLive}
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
            Most recent DNS queries in the pipeline. Every row has been scored; any query
            above zero produces an alert, and High or Critical alerts auto-open a case. Open
            an alert to inspect its features and triage it.
          </p>

          {error && <div className="sim-result-banner error" role="alert">{error}</div>}

          <div className="telemetry-table-wrapper">
            <table className="telemetry-table">
              <thead>
                <tr>
                  <th>Time (UTC)</th>
                  <th>Source</th>
                  <th>Type</th>
                  <th>Queried domain</th>
                  <th>H(X)</th>
                  <th>Sub len</th>
                  <th>Encoding</th>
                  <th>Verdict</th>
                  <th>Alert</th>
                </tr>
              </thead>
              <tbody>
                {isLoading && queries.length === 0 ? (
                  <tr>
                    <td colSpan="9" className="telemetry-empty">Loading query stream…</td>
                  </tr>
                ) : visibleQueries.length === 0 ? (
                  <tr>
                    <td colSpan="9" className="telemetry-empty">
                      {queries.length === 0
                        ? 'No telemetry yet — ingest a log or run a simulation first.'
                        : 'No alerting rows in the current sample.'}
                    </td>
                  </tr>
                ) : (
                  visibleQueries.map((query) => {
                    const entropy = typeof query.entropy === 'number' ? query.entropy.toFixed(2) : '—';
                    const severity = (query.severity || '').toUpperCase();
                    const isThreat = Boolean(query.alert_id) || Boolean(query.risk_score && query.risk_score > 0 && !query.is_whitelisted);
                    const clickable = Boolean(query.alert_id) && Boolean(onOpenAlert);

                    const ratio = typeof query.entropy_ratio === 'number'
                      ? query.entropy_ratio
                      : (typeof query.entropy === 'number'
                        ? (() => {
                          const length = payloadSampleLength(query.domain);
                          const ceiling = length >= 2 ? Math.log2(Math.min(length, 37)) : 0;
                          return ceiling > 0 ? query.entropy / ceiling : 0;
                        })()
                        : 0);

                    return (
                      <tr
                        key={query.id}
                        className={`${isThreat ? 'threat-row' : ''} ${clickable ? 'is-clickable' : ''}`}
                        onClick={clickable ? () => openAlert(query.alert_id) : undefined}
                        onKeyDown={clickable ? (event) => {
                          if (event.target !== event.currentTarget) return;
                          if (event.key === 'Enter' || event.key === ' ') {
                            event.preventDefault();
                            openAlert(query.alert_id);
                          }
                        } : undefined}
                        tabIndex={clickable ? 0 : undefined}
                        title={clickable ? `Open alert #${query.alert_id}` : undefined}
                        aria-label={clickable
                          ? `Open alert ${query.alert_id} for ${query.domain}`
                          : undefined}
                      >
                        <td className="mono text-muted" title={formatDateTime(query.timestamp)}>
                          {query.timestamp ? formatClock(new Date(query.timestamp)) : '—'}
                        </td>
                        <td className="mono">{query.source_ip}</td>
                        <td>
                          <span className="record-type-tag">{query.qtype_name || 'A'}</span>
                        </td>
                        <td className="mono domain-stream-cell" title={query.domain}>
                          {query.domain}
                        </td>
                        <td className={`mono ${ratio >= 0.80 ? 'entropy-high' : ''}`}>{entropy}</td>
                        <td className="mono">{query.subdomain_length ?? 0}</td>
                        <td>
                          <span className="whitelist-source">{query.encoding || 'ascii'}</span>
                        </td>
                        <td>
                          {query.is_whitelisted ? (
                            <span className="verdict-badge benign">Whitelisted</span>
                          ) : isThreat ? (
                            <span
                              className={`verdict-badge ${severity.toLowerCase() || 'medium'}`}
                              style={{ color: SEVERITY_COLORS[severity] || SEVERITY_COLORS.MEDIUM }}
                            >
                              {severity || 'ALERT'} {query.risk_score}
                            </span>
                          ) : (
                            <span className="verdict-badge benign">Benign</span>
                          )}
                        </td>
                        <td>
                          {clickable ? (
                            <button
                              className="telemetry-alert-link"
                              onClick={(event) => {
                                event.stopPropagation();
                                openAlert(query.alert_id);
                              }}
                              aria-label={`Open alert ${query.alert_id}`}
                            >
                              <span className="mono">#{query.alert_id}</span>
                              <ChevronRightIcon size={11} />
                            </button>
                          ) : (
                            <span className="text-muted">—</span>
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
