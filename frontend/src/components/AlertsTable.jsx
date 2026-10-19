import React, { useRef, useEffect } from 'react';
import { SearchIcon, XIcon, ActivityIcon } from './Icons';

const SEVERITY_COLORS = {
  CRITICAL: '#d3564f',
  HIGH:     '#cf8748',
  MEDIUM:   '#6b8fb5',
  LOW:      '#7fa583',
};

const STATUS_CONFIG = {
  'OPEN':           { label: 'Open',        color: '#d3564f', bg: 'rgba(211,86,79,0.12)' },
  'INVESTIGATING':  { label: 'Investigating', color: '#cf8748', bg: 'rgba(207,135,72,0.12)' },
  'CONTAINED':      { label: 'Contained',   color: '#6b8fb5', bg: 'rgba(107,143,181,0.12)' },
  'RESOLVED':       { label: 'Resolved',    color: '#7fa583', bg: 'rgba(127,165,131,0.12)' },
  'FALSE POSITIVE': { label: 'False pos.',  color: '#6b6b76', bg: 'rgba(107,107,118,0.12)' },
};

function formatTimestamp(ts) {
  if (!ts) return '—';
  try {
    const d = new Date(ts);
    if (isNaN(d.getTime())) return '—';
    return d.toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false
    });
  } catch {
    return '—';
  }
}

function highlightMatch(text, query) {
  if (!query || !text) return text || '';
  const escaped = query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const parts = String(text).split(new RegExp(`(${escaped})`, 'gi'));
  return parts.map((part, i) =>
    part.toLowerCase() === query.toLowerCase()
      ? <mark key={i} className="search-match">{part}</mark>
      : part
  );
}

export function AlertsTable({
  alerts,
  filteredAlerts,
  filterSeverity,
  setFilterSeverity,
  filterStatus,
  setFilterStatus,
  searchQuery,
  setSearchQuery,
  sortConfig,
  onSort,
  onStatusChange,
  onSelectAlert,
  selectedAlertId,
  density = 'normal',
  isLoading = false,
}) {
  const searchInputRef = useRef(null);

  // Global Ctrl+K shortcut
  useEffect(() => {
    const handler = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        searchInputRef.current?.focus();
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  const hasFilters = filterSeverity !== 'ALL' || filterStatus !== 'ALL' || searchQuery.trim() !== '';

  const clearFilters = () => {
    setFilterSeverity('ALL');
    setFilterStatus('ALL');
    setSearchQuery('');
  };

  const getSortIcon = (key) => {
    if (sortConfig.key !== key) return <span className="sort-indicator neutral">⇅</span>;
    return <span className="sort-indicator active">{sortConfig.dir === 'desc' ? '↓' : '↑'}</span>;
  };

  return (
    <div className="panel table-panel">
      {/* Table Toolbar */}
      <div className="table-toolbar">
        <div className="toolbar-left">
          <div className="search-input-wrapper">
            <SearchIcon size={14} className="search-icon" />
            <input
              ref={searchInputRef}
              type="text"
              className="table-search"
              placeholder="Search domains, IP addresses, indicators…"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              aria-label="Filter alerts"
            />
            {searchQuery && (
              <button className="search-clear-btn" onClick={() => setSearchQuery('')} aria-label="Clear search">
                <XIcon size={12} />
              </button>
            )}
            <kbd className="search-shortcut">Ctrl+K</kbd>
          </div>

          {/* Severity Pills */}
          <div className="filter-pill-group" role="tablist" aria-label="Filter severity">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => (
              <button
                key={sev}
                className={`filter-pill ${filterSeverity === sev ? 'active' : ''}`}
                style={filterSeverity === sev && sev !== 'ALL' ? { color: SEVERITY_COLORS[sev] } : {}}
                onClick={() => setFilterSeverity(sev)}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>

        <div className="toolbar-right">
          {/* Status Select */}
          <select
            className="filter-select"
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
            aria-label="Filter by alert status"
          >
            <option value="ALL">All Statuses</option>
            <option value="OPEN">Open</option>
            <option value="INVESTIGATING">Investigating</option>
            <option value="CONTAINED">Contained</option>
            <option value="RESOLVED">Resolved</option>
            <option value="FALSE POSITIVE">False Positive</option>
          </select>

          {hasFilters && (
            <button className="btn-clear-filter" onClick={clearFilters}>
              Reset Filters
            </button>
          )}

          <div className="table-count-badge">
            <strong>{filteredAlerts.length}</strong>
            <span>{filteredAlerts.length === 1 ? 'alert' : 'alerts'}</span>
          </div>
        </div>
      </div>

      {/* Responsive Table Container */}
      <div className={`table-scroll-container density-${density}`}>
        <table className="soc-table">
          <thead>
            <tr>
              <th className="th-id" onClick={() => onSort('id')}>ID {getSortIcon('id')}</th>
              <th className="th-sev" onClick={() => onSort('severity')}>Severity {getSortIcon('severity')}</th>
              <th className="th-domain" onClick={() => onSort('domain')}>Domain &amp; Record {getSortIcon('domain')}</th>
              <th className="th-ip" onClick={() => onSort('source_ip')}>Source IP {getSortIcon('source_ip')}</th>
              <th className="th-risk" onClick={() => onSort('risk_score')}>Risk Score {getSortIcon('risk_score')}</th>
              <th className="th-entropy" onClick={() => onSort('entropy')}>Entropy {getSortIcon('entropy')}</th>
              <th className="th-encoding">Encoding</th>
              <th className="th-trigger">Primary indicator</th>
              <th className="th-time" onClick={() => onSort('created_at')}>Time {getSortIcon('created_at')}</th>
              <th className="th-status" onClick={() => onSort('status')}>Status {getSortIcon('status')}</th>
              <th className="th-action">Triage</th>
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              <tr>
                <td colSpan="11" className="table-state-cell">
                  <div className="table-loading-wrap">
                    <div className="table-spinner" />
                    <span>Querying threat telemetry database…</span>
                  </div>
                </td>
              </tr>
            ) : filteredAlerts.length === 0 ? (
              <tr>
                <td colSpan="11" className="table-state-cell">
                  <div className="table-empty-wrap">
                    <SearchIcon size={28} color="#475569" />
                    <p>No security alerts matched the selected filters.</p>
                    {hasFilters && (
                      <button className="btn-action primary" onClick={clearFilters}>
                        Clear All Filter Criteria
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ) : (
              filteredAlerts.map(alert => {
                const isSelected = selectedAlertId === alert.id;
                const statusCfg = STATUS_CONFIG[alert.status] || STATUS_CONFIG['OPEN'];
                const sevColor = SEVERITY_COLORS[(alert.severity || 'LOW').toUpperCase()] || '#6b8fb5';
                const entropyVal = typeof alert.entropy === 'number' ? alert.entropy.toFixed(2) : '—';

                return (
                  <tr
                    key={alert.id}
                    className={`alert-row ${isSelected ? 'row-selected' : ''}`}
                    onClick={() => onSelectAlert(alert)}
                  >
                    {/* ID */}
                    <td className="td-id mono">
                      #{String(alert.id).padStart(4, '0')}
                    </td>

                    {/* Severity */}
                    <td className="td-sev">
                      <span className="badge-severity" style={{ borderColor: `${sevColor}44`, color: sevColor, background: `${sevColor}14` }}>
                        <span className="sev-dot" style={{ background: sevColor }} />
                        {alert.severity}
                      </span>
                    </td>

                    {/* Domain */}
                    <td className="td-domain">
                      <div className="domain-cell-wrap">
                        <span className="record-type-tag">{alert.qtype_name || 'A'}</span>
                        <span className="domain-text mono" title={alert.domain}>
                          {searchQuery ? highlightMatch(alert.domain, searchQuery) : alert.domain}
                        </span>
                      </div>
                    </td>

                    {/* Source IP */}
                    <td className="td-ip mono">
                      {searchQuery ? highlightMatch(alert.source_ip, searchQuery) : alert.source_ip}
                    </td>

                    {/* Risk Score */}
                    <td className="td-risk">
                      <div className="risk-score-wrapper">
                        <span className="risk-num mono" style={{ color: sevColor }}>
                          {alert.risk_score}
                        </span>
                        <div className="risk-track">
                          <div
                            className="risk-bar-fill"
                            style={{ width: `${alert.risk_score}%`, background: sevColor }}
                          />
                        </div>
                      </div>
                    </td>

                    {/* Entropy — raw value with the length-normalised ratio as context */}
                    <td
                      className="td-entropy mono"
                      title={
                        typeof alert.entropy_ratio === 'number'
                          ? `${Math.round(alert.entropy_ratio * 100)}% of the maximum achievable for a ${alert.subdomain_length || alert.query_length}-char payload`
                          : undefined
                      }
                    >
                      <span className={alert.entropy_ratio >= 0.8 ? 'entropy-high' : ''}>
                        {entropyVal}
                      </span>
                    </td>

                    {/* Encoding profile inferred from the label composition */}
                    <td className="td-encoding">
                      <span className="whitelist-source">{alert.encoding || 'ascii'}</span>
                    </td>

                    {/* Primary indicator */}
                    <td className="td-trigger" title={alert.detection_reason}>
                      <span className="trigger-snippet">
                        {searchQuery ? highlightMatch(alert.detection_reason, searchQuery) : alert.detection_reason}
                      </span>
                    </td>

                    {/* Time */}
                    <td className="td-time">
                      {formatTimestamp(alert.created_at)}
                    </td>

                    {/* Status Dropdown */}
                    <td className="td-status" onClick={(e) => e.stopPropagation()}>
                      <select
                        className="inline-status-select"
                        value={alert.status || 'OPEN'}
                        style={{ color: statusCfg.color, borderColor: `${statusCfg.color}44`, background: statusCfg.bg }}
                        onChange={(e) => onStatusChange(alert.id, e.target.value, alert.domain)}
                        aria-label={`Update status for ${alert.domain}`}
                      >
                        <option value="OPEN">Open</option>
                        <option value="INVESTIGATING">Investigating</option>
                        <option value="CONTAINED">Contained</option>
                        <option value="RESOLVED">Resolved</option>
                        <option value="FALSE POSITIVE">False Positive</option>
                      </select>
                    </td>

                    {/* Action */}
                    <td className="td-action" onClick={(e) => e.stopPropagation()}>
                      <button
                        className="btn-inspect"
                        onClick={() => onSelectAlert(alert)}
                        title="Open deep forensic inspection panel"
                      >
                        <ActivityIcon size={12} />
                        <span>Inspect</span>
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
