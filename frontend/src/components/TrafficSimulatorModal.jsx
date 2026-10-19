import React, { useEffect, useState } from 'react';
import { XIcon, PlayIcon, RefreshIcon, TerminalIcon, DatabaseIcon } from './Icons';

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

  // Escape closes the modal, matching the drawer and telemetry panel.
  useEffect(() => {
    if (!isOpen) return undefined;
    const handler = (event) => { if (event.key === 'Escape') onClose(); };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const handleRunSim = async () => {
    setIsSimulating(true);
    setResultMessage(null);
    try {
      const result = await onSimulate(scenario, count);
      setResultMessage({
        type: 'success',
        text: result?.message || `Injected ${count} queries.`,
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
      setResultMessage({
        type: 'success',
        text: `Zeek import: ${result?.inserted ?? 0} new queries, ${result?.skipped ?? 0} duplicates skipped, ${result?.alerts ?? 0} alerts, ${result?.incidents ?? 0} incidents.`,
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
      setResultMessage({
        type: 'success',
        text: `PCAP import: ${result?.inserted ?? 0} new queries, ${result?.skipped ?? 0} duplicates skipped, ${result?.alerts ?? 0} alerts.`,
      });
    } catch (error) {
      setResultMessage({ type: 'error', text: error?.message || 'PCAP analysis failed.' });
    } finally {
      setIsIngestingPcap(false);
    }
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-container" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
        <div className="modal-header">
          <div className="modal-title-wrap">
            <PlayIcon size={15} color="var(--accent)" />
            <h3>Traffic simulator</h3>
          </div>
          <button className="modal-close-btn" onClick={onClose} aria-label="Close modal">
            <XIcon size={18} />
          </button>
        </div>

        <div className="modal-body">
          <p className="modal-description">
            Push synthetic queries through the real scoring pipeline. Benign scenarios exist to prove the whitelist suppresses them — if one raises an alert, the rule set needs work.
          </p>

          {/* Scenario Selection */}
          <div className="sim-group">
            <label className="sim-label">Scenario</label>
            <div className="sim-scenario-grid">
              <label className={`sim-card ${scenario === 'all' ? 'active' : ''}`}>
                <input
                  type="radio"
                  name="scenario"
                  value="all"
                  checked={scenario === 'all'}
                  onChange={() => setScenario('all')}
                />
                <div className="sim-card-title">Mixed traffic</div>
                <div className="sim-card-desc">All four profiles in one batch.</div>
              </label>

              <label className={`sim-card ${scenario === 'base32_exfil' ? 'active' : ''}`}>
                <input
                  type="radio"
                  name="scenario"
                  value="base32_exfil"
                  checked={scenario === 'base32_exfil'}
                  onChange={() => setScenario('base32_exfil')}
                />
                <div className="sim-card-title">Base32 exfiltration</div>
                <div className="sim-card-desc">Alphanumeric chunks packed into deep labels.</div>
              </label>

              <label className={`sim-card ${scenario === 'c2_beaconing' ? 'active' : ''}`}>
                <input
                  type="radio"
                  name="scenario"
                  value="c2_beaconing"
                  checked={scenario === 'c2_beaconing'}
                  onChange={() => setScenario('c2_beaconing')}
                />
                <div className="sim-card-title">dnscat2 beaconing</div>
                <div className="sim-card-desc">TXT queries carrying a dnscat2 session label.</div>
              </label>

              <label className={`sim-card ${scenario === 'iodine_hex' ? 'active' : ''}`}>
                <input
                  type="radio"
                  name="scenario"
                  value="iodine_hex"
                  checked={scenario === 'iodine_hex'}
                  onChange={() => setScenario('iodine_hex')}
                />
                <div className="sim-card-title">Iodine hex tunnel</div>
                <div className="sim-card-desc">Pure-hex chunks with no natural word shape.</div>
              </label>

              <label className={`sim-card ${scenario === 'benign' ? 'active' : ''}`}>
                <input
                  type="radio"
                  name="scenario"
                  value="benign"
                  checked={scenario === 'benign'}
                  onChange={() => setScenario('benign')}
                />
                <div className="sim-card-title">Benign browsing</div>
                <div className="sim-card-desc">Everyday corporate lookups — should score zero.</div>
              </label>
            </div>
          </div>

          {/* Query Count */}
          <div className="sim-group">
            <div className="sim-count-row">
              <label className="sim-label">Queries</label>
              <span className="mono count-display">{count} queries</span>
            </div>
            <input
              type="range"
              min="1"
              max="15"
              value={count}
              onChange={(e) => setCount(parseInt(e.target.value, 10))}
              className="sim-slider"
            />
          </div>

          {/* Action Trigger */}
          <button
            className="btn-trigger-sim primary"
            onClick={handleRunSim}
            disabled={isSimulating}
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

          {/* Ingestion Pipelines Section */}
          <div className="pipeline-ingest-section">
            <div className="pipeline-title">Import from file</div>
            <div className="pipeline-buttons">
              <button
                className="btn-pipeline"
                onClick={handleZeek}
                disabled={isIngestingZeek}
              >
                <TerminalIcon size={14} />
                <span>{isIngestingZeek ? 'Importing…' : 'zeek/logs/dns.log'}</span>
              </button>

              <button
                className="btn-pipeline"
                onClick={handlePcap}
                disabled={isIngestingPcap}
              >
                <DatabaseIcon size={14} />
                <span>{isIngestingPcap ? 'Parsing…' : 'test_traffic.pcap'}</span>
              </button>
            </div>
          </div>

          {/* Result Banner */}
          {resultMessage && (
            <div className={`sim-result-banner ${resultMessage.type}`}>
              {resultMessage.text}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
