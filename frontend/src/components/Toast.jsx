import React from 'react';
import {
  CheckCircleIcon, AlertTriangleIcon, AlertOctagonIcon, InfoIcon, XIcon,
} from './Icons';

const ICONS = {
  success: CheckCircleIcon,
  error: AlertOctagonIcon,
  warning: AlertTriangleIcon,
  info: InfoIcon,
};

export function ToastContainer({ toasts, onDismiss }) {
  if (!toasts || toasts.length === 0) return null;

  return (
    <div className="toast-container" role="status" aria-live="polite">
      {toasts.map((toast) => {
        const type = toast.type || 'info';
        const IconComponent = ICONS[type] || InfoIcon;

        return (
          <div
            key={toast.id}
            // `exiting` drives the outbound animation; the previous class names
            // (toast-enter / toast-exit) had no matching CSS rule.
            className={`toast toast-${type}${toast.exiting ? ' exiting' : ''}`}
          >
            <span className="toast-icon">
              <IconComponent size={14} />
            </span>
            <div className="toast-msg-wrap">
              {toast.title && <div className="toast-title">{toast.title}</div>}
              <div className="toast-msg">{toast.message}</div>
            </div>
            <button
              className="toast-close"
              onClick={() => onDismiss(toast.id)}
              aria-label="Dismiss notification"
            >
              <XIcon size={12} />
            </button>
          </div>
        );
      })}
    </div>
  );
}
