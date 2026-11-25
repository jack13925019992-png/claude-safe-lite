import { useState } from "react";
import { api } from "../api";
import type { HumanizedError } from "../types";

interface ErrorBannerProps {
  error: HumanizedError;
  variant?: "danger" | "warning";
  onDismiss?: () => void;
  actionLabel?: string;
  onAction?: () => void;
}

export function ErrorBanner({
  error,
  variant = "danger",
  onDismiss,
  actionLabel,
  onAction,
}: ErrorBannerProps) {
  const [expanded, setExpanded] = useState(false);

  const isBrowserMissing = error.code === "BROWSER_NOT_FOUND";

  return (
    <div className={`human-error-box ${variant}`}>
      <div className="human-error-main">
        <div className="human-error-text">
          <span className="human-error-icon">
            {variant === "danger" ? "⚠" : "⚡"}
          </span>
          <span>{error.userMessage}</span>
        </div>
        <div className="human-error-actions">
          {isBrowserMissing && (
            <button
              type="button"
              className="btn btn-sm btn-primary"
              onClick={() => {
                void api.openExternal("https://brave.com/download/");
              }}
            >
              下载 Brave 浏览器
            </button>
          )}
          {actionLabel && onAction && (
            <button
              type="button"
              className="btn btn-sm btn-danger-solid"
              onClick={onAction}
            >
              {actionLabel}
            </button>
          )}
          {error.technicalDetail && (
            <button
              type="button"
              className="btn-link"
              onClick={() => setExpanded((v) => !v)}
            >
              {expanded ? "收起技术细节" : "查看技术细节"}
            </button>
          )}
          {onDismiss && (
            <button
              type="button"
              className="btn-icon-close"
              title="关闭提示"
              onClick={onDismiss}
            >
              ×
            </button>
          )}
        </div>
      </div>
      {expanded && error.technicalDetail && (
        <pre className="human-error-tech">
          [{error.code}] {error.technicalDetail}
        </pre>
      )}
    </div>
  );
}
