// 前后端严格对齐的数据模型与事件载荷类型定义（对应需求文档第 8 节）

export type LightStatus = "green" | "yellow" | "red" | "pending" | "checking";

export type CheckId =
  | "proxy_connection"
  | "exit_ip_country"
  | "ip_risk_score"
  | "claude_access"
  | "dns_leak";

export type LogKind = "app" | "check" | "launch";

export type BrowserLifecycleState = "idle" | "launching" | "running" | "exited";

export type TripKind = "ip_or_dns_leak" | "proxy_disconnected";

export interface HumanizedError {
  code: string;
  userMessage: string;
  technicalDetail: string;
}

export interface ProxyView {
  id: string;
  name: string;
  host: string;
  port: number;
  authEnabled: boolean;
  username: string;
  hasPassword: boolean;
}

export interface SaveProxyInput {
  id?: string | null;
  name: string;
  host: string;
  port: number;
  authEnabled: boolean;
  username: string;
  password?: string | null;
}

export interface ParsedProxyDraft {
  host: string;
  port: number;
  authEnabled: boolean;
  username: string;
  password: string;
}

export interface AppSettings {
  customBrowserPath: string | null;
  safeModeEnabled: boolean;
  watchdogIntervalSec: number;
  autoStartEnabled: boolean;
}

export interface BrowserProfileEnv {
  id: string;
  name: string;
}

export interface BrowserEnvStateResponse {
  browserEnvs: BrowserProfileEnv[];
  activeBrowserEnvId: string;
}

export interface CheckItemResult {
  index: number;
  id: CheckId;
  title: string;
  critical: boolean;
  status: LightStatus;
  summary: string;
  error: HumanizedError | null;
  latencyMs: number | null;
}

export interface CheckReport {
  proxyId: string;
  proxyName: string;
  isRunning: boolean;
  completedAt: string | null;
  exitIp: string | null;
  countryCode: string | null;
  countryDisplay: string | null;
  isp: string | null;
  riskScore: number | null;
  items: CheckItemResult[];
}

export type ForwarderStateSnapshot =
  | { status: "stopped" }
  | {
      status: "running";
      port: number;
      activeConnections: number;
      leaseCount: number;
    }
  | {
      status: "tripped";
      reason: string;
    };

export interface CircuitBreakerSnapshot {
  locked: boolean;
  reason: string | null;
  tripKind: TripKind | null;
  triggeredAt: string | null;
  lastCheckAt: string | null;
  monitoringActive: boolean;
}

export interface WatchdogAlertPayload {
  tripKind: TripKind;
  notificationTitle: string;
  notificationBody: string;
  bannerError: HumanizedError;
  triggeredAt: string;
}

export interface LicenseStatusView {
  authorized: boolean;
  machineCode: string;
  holderName: string | null;
  holderPhone: string | null;
  isPermanent: boolean;
  expiresAt: string | null;
  daysRemaining: number | null;
  machineBound: boolean;
  expiredMessage: string | null;
}

export interface ActivateLicenseInput {
  name: string;
  phone: string;
  licenseCode: string;
  proxyInput?: SaveProxyInput | null;
}

export interface AppFullStateResponse {
  license: LicenseStatusView;
  proxies: ProxyView[];
  activeProxyId: string | null;
  settings: AppSettings;
  browserEnvs: BrowserProfileEnv[];
  activeBrowserEnvId: string;
  browserState: BrowserLifecycleState;
  runningProxyId: string | null;
  runningBrowserEnvId: string | null;
  forwarderState: ForwarderStateSnapshot;
  circuitBreaker: CircuitBreakerSnapshot;
  latestReport: CheckReport | null;
  recoveredFromBackup: boolean;
}

export interface DetectedBrowser {
  kind: "custom" | "brave" | "chrome";
  path: string;
}

export type LaunchBrowserResponse =
  | {
      outcome: "launched";
      browser: DetectedBrowser;
      forwarderPort: number;
    }
  | {
      outcome: "needsWarningConfirm";
      warnings: CheckItemResult[];
      report: CheckReport;
    }
  | {
      outcome: "blocked";
      reason: HumanizedError;
      report: CheckReport | null;
    };

export interface ResetEnvOptions {
  cleanBrowserProfiles: boolean;
  cleanLogs: boolean;
  clearProxies: boolean;
  restoreDefaultSettings: boolean;
}

export interface ResetSummary {
  message: string;
}

export interface ProxyListResponse {
  proxies: ProxyView[];
  activeProxyId: string | null;
}
