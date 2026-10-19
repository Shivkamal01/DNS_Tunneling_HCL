import React from 'react';
import {
  ShieldIcon, AlertOctagonIcon, ActivityIcon,
  CheckCircleIcon, DatabaseIcon,
} from './Icons';

function formatBytes(bytes) {
  if (!bytes || bytes <= 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export function MetricsOverview({ stats, avgRisk, totalExfilBytes }) {
  const pendingPct = stats.total > 0 ? Math.round((stats.open / stats.total) * 100) : 0;
  const resolvedPct = stats.total > 0 ? Math.round((stats.resolved / stats.total) * 100) : 0;

  return (
    <div className="metrics-grid" role="region" aria-label="Detection metrics">
      <div className="metric-card blue">
        <div className="metric-header">
          <span className="metric-title">Total alerts</span>
          <div className="metric-icon-bubble blue">
            <ShieldIcon size={13} />
          </div>
        </div>
        <div className="metric-value-row">
          <span className="metric-value">{stats.total}</span>
          <span className="metric-subtext">avg risk {avgRisk}</span>
        </div>
        <div className="metric-footer">
          <span className="metric-badge neutral">Entropy + lexical engine</span>
        </div>
      </div>

      <div className="metric-card critical">
        <div className="metric-header">
          <span className="metric-title">Critical</span>
          <div className="metric-icon-bubble red">
            <AlertOctagonIcon size={13} />
          </div>
        </div>
        <div className="metric-value-row">
          <span className="metric-value red-text">{stats.critical}</span>
          <span className={`metric-subtext ${stats.critical > 0 ? 'alert-text' : 'success-text'}`}>
            {stats.critical > 0 ? 'needs triage' : 'none open'}
          </span>
        </div>
        <div className="metric-footer">
          <span className={`metric-badge ${stats.critical > 0 ? 'red' : 'green'}`}>
            {stats.critical > 0 ? 'Escalated' : 'Nominal'}
          </span>
        </div>
      </div>

      <div className="metric-card orange">
        <div className="metric-header">
          <span className="metric-title">Open</span>
          <div className="metric-icon-bubble orange">
            <ActivityIcon size={13} />
          </div>
        </div>
        <div className="metric-value-row">
          <span className="metric-value orange-text">{stats.open}</span>
          <span className="metric-subtext">{pendingPct}% awaiting</span>
        </div>
        <div className="metric-footer">
          <span className="metric-badge orange">
            {stats.activeIncidents} active {stats.activeIncidents === 1 ? 'incident' : 'incidents'}
          </span>
        </div>
      </div>

      <div className="metric-card green">
        <div className="metric-header">
          <span className="metric-title">Closed</span>
          <div className="metric-icon-bubble green">
            <CheckCircleIcon size={13} />
          </div>
        </div>
        <div className="metric-value-row">
          <span className="metric-value green-text">{stats.resolved}</span>
          <span className="metric-subtext">{resolvedPct}% resolved</span>
        </div>
        <div className="metric-footer">
          <span className="metric-badge green">
            {stats.suppressed} suppressed by whitelist
          </span>
        </div>
      </div>

      <div className="metric-card purple">
        <div className="metric-header">
          <span className="metric-title">Est. exfiltration</span>
          <div className="metric-icon-bubble purple">
            <DatabaseIcon size={13} />
          </div>
        </div>
        <div className="metric-value-row">
          <span className="metric-value purple-text">{formatBytes(totalExfilBytes)}</span>
        </div>
        <div className="metric-footer">
          <span className="metric-badge purple">From flagged queries only</span>
        </div>
      </div>
    </div>
  );
}
