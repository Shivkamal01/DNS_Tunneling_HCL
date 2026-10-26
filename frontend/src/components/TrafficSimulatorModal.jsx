import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  XIcon, PlayIcon, RefreshIcon, TerminalIcon, DatabaseIcon, AlertCircleIcon,
} from './Icons';
import {
  useBodyScrollLock,
  useEscapeKey,
  useFocusReturn,
  useFocusTrap,
} from '../utils/overlay';

const SCENARIOS = [
  {
    key: 'all',
    title: 'Mixed traffic',
    desc: 'One batch across every profile — useful for a broad smoke test.',
    profiles: 14,
  },
  {
    key: 'base32_exfil',
    title: 'Base32 exfiltration',
    desc: 'Alphanumeric chunks packed into deep labels.',
    profiles: 3,
  },
  {
    key: 'c2_beaconing',
    title: 'dnscat2 beaconing',
    desc: 'TXT queries carrying a dnscat2 session label.',
    profiles: 3,
  },
  {
    key: 'iodine_hex',
    title: 'Iodine hex tunnel',
    desc: 'Pure-hex chunks with no natural word shape.',
    profiles: 3,
  },
  {
    key: 'benign',
    title: 'Benign browsing',
    desc: 'Everyday corporate lookups — should score zero.',
    profiles: 5,
  },
];

const MAX_BY_SCENARIO = SCENARIOS.reduce((acc, scenario) => {
  acc[scenario.key] = scenario.profiles;
  return acc;
}, {});

export function TrafficSimulatorModal({
  isOpen,
  onClose,
  onSimulate,
  onIngestZeek,
  onIngestPcap,
}) {
  const [scenario, setScenario] = useState('all');
  const [count, setCount] = useState(5);
  const [isSimulating, setIsSimulating] = useState(false);
  const [isIngestingZeek, setIsIngestingZeek] = useState(false);
  const [isIngestingPcap, setIsIngestingPcap] = useState(false);
  const [resultMessage, setResultMessage] = useState(null);
  const modalRef = useRef(null);

  const maxCount = MAX_BY_SCENARIO[scenario] || 5;
  const selectedScenario = useMemo(
    () => SCENARIOS.find((item) => item.key === scenario),
    [scenario],
  );

  useBodyScrollLock(isOpen);
  useFocusReturn(isOpen, modalRef);
  useFocusTrap(isOpen, modalRef);
  useEscapeKey(isOpen, onClose);

  // Switching from "Mixed traffic" to a three-profile scenario must not leave
  // the slider promising fourteen queries that the backend cannot supply.
  useEffect(() => {
    setCount((current) => Math.min(current, maxCount));
  }, [maxCount]);

  // Reset transient output when the panel closes so reopening shows the
  // controls fresh rather than a stale result from a previous run.
  useEffect(() => {
    if (!isOpen) setResultMessage(null);
  }, [isOpen]);

  const isBusy = isSimulating || isIngestingZeek || isIngestingPcap;

  if (!isOpen) return null;

  const handleRunSim = async () => {
    setIsSimulating(true);
    setResultMessage(null);
    try {
      const result = await onSimulate(scenario, count);
      const alerts = result?.alerts_generated ?? 0;
      const incidents = result?.incidents_generated ?? 0;
      const failed = result?.failed ?? 0;
      const attempted = result?.attempted_count ?? count;
      const resultType = failed === 0
        ? 'success'
        : (failed >= attempted ? 'error' : 'warning');

      setResultMessage({
        type: resultType,
        text: `${result?.message || `Injected ${count} queries.`}`
          + (failed ? ` ${failed} record${failed === 1 ? '' : 's'} failed and were skipped.` : ''),
        meta: `${alerts} alerts · ${incidents} incidents escalated`,
      });
    } catch (error) {
      setResultMessage({ type: 'error', text: error?.message || 'Simulation failed.' });
    } finally {
      setIsSimulating(false);
    }
  };

  const handleZeek = async () => {
    setIsIngestingZeek(true);
    setResultMessage(null);
    try {
      const result = await onIngestZeek();
      const failed = result?.failed ?? 0;
      setResultMessage({
        type: failed > 0 ? 'warning' : 'success',
        text: `Zeek import: ${result?.inserted ?? 0} new queries, ${result?.skipped ?? 0} duplicates skipped, ${result?.alerts ?? 0} alerts`
          + (failed ? `, ${failed} failed` : '') + '.',
        meta: `${result?.incidents ?? 0} incidents escalated`,
      });
    } catch (error) {
      setResultMessage({ type: 'error', text: error?.message || 'Zeek ingestion failed.' });
    } finally {
      setIsIngestingZeek(false);
    }
  };

  const handlePcap = async () => {
    setIsIngestingPcap(true);
    setResultMessage(null);
    try {
      const result = await onIngestPcap();
      const failed = result?.failed ?? 0;
      setResultMessage({
        type: failed > 0 ? 'warning' : 'success',
        text: `PCAP import: ${result?.inserted ?? 0} new queries, ${result?.skipped ?? 0} duplicates skipped, ${result?.alerts ?? 0} alerts`
          + (failed ? `, ${failed} failed` : '') + '.',
        meta: `${result?.incidents ?? 0} incidents escalated`,
      });
    } catch (error) {
      setResultMessage({ type: 'error', text: error?.message || 'PCAP analysis failed.' });
    } finally {
      setIsIngestingPcap(false);
    }
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div
        className="modal-container"
        ref={modalRef}
        tabIndex={-1}
        onClick={(event) => event.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-labelledby="simulator-title"
      >
        <div className="modal-header">
          <div className="modal-title-wrap">
            <PlayIcon size={15} color="var(--accent)" />
            <div>
              <h3 id="simulator-title">Traffic simulator</h3>
              <span className="modal-subtitle">Synthetic queries, real scoring engine</span>
            </div>
          </div>
          <button className="modal-close-btn" onClick={onClose} aria-label="Close modal">
            <XIcon size={18} />
          </button>
        </div>

        <div className="modal-body">
          <p className="modal-description">
            Push synthetic queries through the same feature extraction and scoring path as live
            telemetry. Benign scenarios use ordinary corporate lookups and should stay at zero; a
            raised alert there means the scoring thresholds or whitelist need review.
          </p>

          <div className="sim-live-warning" role="note">
            <AlertCircleIcon size={14} />
            <span>
              This writes to the connected database. Repeated runs create new queries, alerts and
              incidents, just like a live sensor.
            </span>
          </div>

          <div className="sim-group">
            <label className="sim-label">Scenario</label>
            <div className="sim-scenario-grid">
              {SCENARIOS.map((item) => (
                <label
                  key={item.key}
                  className={`sim-card ${scenario === item.key ? 'active' : ''}`}
                >
                  <input
                    type="radio"
                    name="scenario"
                    value={item.key}
                    checked={scenario === item.key}
                    onChange={() => setScenario(item.key)}
                    disabled={isBusy}
                  />
                  <div className="sim-card-title-row">
                    <div className="sim-card-title">{item.title}</div>
                    <span className="sim-card-count mono">{item.profiles}</span>
                  </div>
                  <div className="sim-card-desc">{item.desc}</div>
                </label>
              ))}
            </div>
          </div>

          <div className="sim-group">
            <div className="sim-count-row">
              <label className="sim-label" htmlFor="sim-count">Queries</label>
              <span className="mono count-display">
                {count} {count === 1 ? 'query' : 'queries'}
                <span className="count-max"> · max {selectedScenario?.profiles ?? maxCount}</span>
              </span>
            </div>
            <input
              id="sim-count"
              type="range"
              min="1"
              max={maxCount}
              value={count}
              onChange={(event) => setCount(parseInt(event.target.value, 10))}
              className="sim-slider"
              disabled={isBusy}
            />
            <div className="sim-slider-scale mono">
              <span>1</span>
              <span>{maxCount}</span>
            </div>
          </div>

          <button
            className="btn-trigger-sim primary"
            onClick={handleRunSim}
            disabled={isSimulating || isBusy}
          >
            {isSimulating ? (
              <>
                <RefreshIcon size={14} className="spin-anim" />
                <span>Injecting…</span>
              </>
            ) : (
              <>
                <PlayIcon size={14} />
                <span>Inject {count} {count === 1 ? 'query' : 'queries'}</span>
              </>
            )}
          </button>

          <div className="pipeline-ingest-section">
            <div className="pipeline-title">Import from a bundled capture</div>
            <div className="pipeline-buttons">
              <button
                className="btn-pipeline"
                onClick={handleZeek}
                disabled={isBusy}
                title="Import zeek/logs/dns.log"
              >
                <TerminalIcon size={14} />
                <span>{isIngestingZeek ? 'Importing…' : 'zeek/logs/dns.log'}</span>
              </button>

              <button
                className="btn-pipeline"
                onClick={handlePcap}
                disabled={isBusy}
                title="Parse datasets/suspicious/test_traffic.pcap"
              >
                <DatabaseIcon size={14} />
                <span>{isIngestingPcap ? 'Parsing…' : 'test_traffic.pcap'}</span>
              </button>
            </div>
            <p className="pipeline-hint">
              Both files are already de-duplicated on import, so a second run reports skipped
              rows instead of doubling the dashboard.
            </p>
          </div>

          {resultMessage && (
            <div
              className={`sim-result-banner ${resultMessage.type}`}
              role={resultMessage.type === 'error' ? 'alert' : 'status'}
            >
              <span>{resultMessage.text}</span>
              {resultMessage.meta && <span className="sim-result-meta">{resultMessage.meta}</span>}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
