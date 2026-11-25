import { invoke } from "@tauri-apps/api/core";
import { listen, UnlistenFn } from "@tauri-apps/api/event";
import type {
  ActivateLicenseInput,
  AppFullStateResponse,
  AppSettings,
  BrowserEnvStateResponse,
  BrowserLifecycleState,
  CheckItemResult,
  CheckReport,
  CircuitBreakerSnapshot,
  ForwarderStateSnapshot,
  HumanizedError,
  LaunchBrowserResponse,
  LicenseStatusView,
  LogKind,
  ParsedProxyDraft,
  ProxyListResponse,
  ProxyView,
  ResetEnvOptions,
  ResetSummary,
  SaveProxyInput,
  WatchdogAlertPayload,
} from "./types";

/**
 * 将后端返回的未知异常统一规范化为 HumanizedError（「人话原因 + 建议动作 + 折叠技术细节」）
 */
export function normalizeError(err: unknown): HumanizedError {
  if (err && typeof err === "object") {
    const obj = err as Record<string, unknown>;
    if (typeof obj.userMessage === "string") {
      return {
        code: typeof obj.code === "string" ? obj.code : "ERROR",
        userMessage: obj.userMessage,
        technicalDetail:
          typeof obj.technicalDetail === "string" ? obj.technicalDetail : "",
      };
    }
  }
  if (typeof err === "string") {
    try {
      const parsed = JSON.parse(err) as Record<string, unknown>;
      if (typeof parsed.userMessage === "string") {
        return {
          code: typeof parsed.code === "string" ? parsed.code : "ERROR",
          userMessage: parsed.userMessage,
          technicalDetail:
            typeof parsed.technicalDetail === "string"
              ? parsed.technicalDetail
              : "",
        };
      }
    } catch {
      // 普通字符串错误
    }
    return {
      code: "OPERATION_ERROR",
      userMessage: err,
      technicalDetail: "",
    };
  }
  return {
    code: "UNKNOWN_ERROR",
    userMessage: "操作执行遇到未知错误 → 请重试或查看应用日志定位原因",
    technicalDetail: String(err),
  };
}

export const api = {
  getAppState: () => invoke<AppFullStateResponse>("get_app_state"),

  activateLicense: (input: ActivateLicenseInput) =>
    invoke<LicenseStatusView>("activate_license", { input }),

  deactivateLicense: () => invoke<LicenseStatusView>("deactivate_license"),

  updateSettings: (settings: AppSettings) =>
    invoke<AppSettings>("update_settings", { settings }),

  setBrowserPath: (path: string | null) =>
    invoke<AppSettings>("set_browser_path", { path }),

  listProxies: () => invoke<ProxyListResponse>("list_proxies"),

  saveProxy: (input: SaveProxyInput) =>
    invoke<ProxyView>("save_proxy", { input }),

  duplicateProxy: (id: string) =>
    invoke<ProxyView>("duplicate_proxy", { id }),

  deleteProxy: (id: string) =>
    invoke<string | null>("delete_proxy", { id }),

  setActiveProxy: (id: string) =>
    invoke<ProxyView>("set_active_proxy", { id }),

  parseProxyText: (raw: string) =>
    invoke<ParsedProxyDraft>("parse_proxy_text", { raw }),

  testProxyConnection: (input: SaveProxyInput) =>
    invoke<CheckItemResult>("test_proxy_connection", { input }),

  runChecks: () => invoke<CheckReport>("run_checks"),

  cancelChecks: () => invoke<void>("cancel_checks"),

  launchBrowser: (force: boolean, allowWarnings?: boolean) =>
    invoke<LaunchBrowserResponse>("launch_browser", {
      force,
      allowWarnings: allowWarnings ?? null,
    }),

  closeBrowser: () => invoke<boolean>("close_browser"),

  createBrowserEnv: (name: string) =>
    invoke<BrowserEnvStateResponse>("create_browser_env", { name }),

  setActiveBrowserEnv: (envId: string) =>
    invoke<BrowserEnvStateResponse>("set_active_browser_env", { envId }),

  getDiagnosticReport: () => invoke<string>("get_diagnostic_report"),

  launchClaudeCode: (workdir?: string | null) =>
    invoke<string>("launch_claude_code", {
      workdir: workdir && workdir.trim() ? workdir.trim() : null,
    }),

  launchClaudeDesktop: () => invoke<string>("launch_claude_desktop"),

  readLog: (kind: LogKind, tail = 500) =>
    invoke<string[]>("read_log", { kind, tail }),

  exportLog: (kind: LogKind) =>
    invoke<string | null>("export_log", { kind }),

  clearLog: (kind: LogKind) => invoke<void>("clear_log", { kind }),

  resetEnv: (options: ResetEnvOptions) =>
    invoke<ResetSummary>("reset_env", { options }),

  openExternal: (url: string) => invoke<void>("open_external", { url }),

  hideToTray: () => invoke<void>("hide_to_tray"),

  confirmExitApp: () => invoke<void>("confirm_exit_app"),
};

export const events = {
  onCheckProgress: (handler: (report: CheckReport) => void): Promise<UnlistenFn> =>
    listen<CheckReport>("check-progress", (e) => handler(e.payload)),

  onBrowserState: (
    handler: (state: BrowserLifecycleState) => void,
  ): Promise<UnlistenFn> =>
    listen<BrowserLifecycleState>("browser-state", (e) => handler(e.payload)),

  onForwarderState: (
    handler: (state: ForwarderStateSnapshot) => void,
  ): Promise<UnlistenFn> =>
    listen<ForwarderStateSnapshot>("forwarder-state", (e) => handler(e.payload)),

  onCircuitBreakerState: (
    handler: (state: CircuitBreakerSnapshot) => void,
  ): Promise<UnlistenFn> =>
    listen<CircuitBreakerSnapshot>("circuit-breaker-state", (e) =>
      handler(e.payload),
    ),

  onWatchdogAlert: (
    handler: (alert: WatchdogAlertPayload) => void,
  ): Promise<UnlistenFn> =>
    listen<WatchdogAlertPayload>("watchdog-alert", (e) => handler(e.payload)),

  onWindowCloseRequested: (handler: () => void): Promise<UnlistenFn> =>
    listen("window-close-requested", () => handler()),

  onLicenseState: (
    handler: (state: LicenseStatusView) => void,
  ): Promise<UnlistenFn> =>
    listen<LicenseStatusView>("license-state", (e) => handler(e.payload)),
};
