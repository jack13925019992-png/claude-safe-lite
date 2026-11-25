import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, events, normalizeError } from "./api";
import { ErrorBanner } from "./components/ErrorBanner";
import { LicenseGateView } from "./components/LicenseGateView";
import {
  CreateBrowserEnvModal,
  LogViewerModal,
  ProxyManagerModal,
  ResetEnvModal,
  RiskConfirmModal,
  SettingsModal,
  WatchdogAlertModal,
  WindowCloseProtectionModal,
} from "./components/Modals";
import type {
  AppSettings,
  BrowserLifecycleState,
  BrowserProfileEnv,
  CheckItemResult,
  CheckReport,
  CircuitBreakerSnapshot,
  ForwarderStateSnapshot,
  HumanizedError,
  LicenseStatusView,
  LightStatus,
  ProxyView,
  WatchdogAlertPayload,
} from "./types";

const IS_MAC =
  typeof navigator !== "undefined" &&
  /Mac|iPod|iPhone|iPad/i.test(navigator.userAgent);

const DEFAULT_FIVE_ITEMS: CheckItemResult[] = [
  {
    index: 1,
    id: "proxy_connection",
    title: "代理连接",
    critical: true,
    status: "pending",
    summary: "待检测",
    error: null,
    latencyMs: null,
  },
  {
    index: 2,
    id: "exit_ip_country",
    title: "出口IP国家",
    critical: true,
    status: "pending",
    summary: "待检测",
    error: null,
    latencyMs: null,
  },
  {
    index: 3,
    id: "ip_risk_score",
    title: "IP风险评分",
    critical: false,
    status: "pending",
    summary: "待检测",
    error: null,
    latencyMs: null,
  },
  {
    index: 4,
    id: "claude_access",
    title: "Claude可访问",
    critical: true,
    status: "pending",
    summary: "待检测",
    error: null,
    latencyMs: null,
  },
  {
    index: 5,
    id: "dns_leak",
    title: "DNS泄露",
    critical: false,
    status: "pending",
    summary: "待检测",
    error: null,
    latencyMs: null,
  },
];

function statusLabelText(st: LightStatus): string {
  switch (st) {
    case "green":
      return "通过";
    case "yellow":
      return "警告";
    case "red":
      return "阻断/失败";
    case "checking":
      return "检测中";
    case "pending":
    default:
      return "待定";
  }
}

export default function App() {
  const [bootLoaded, setBootLoaded] = useState(false);
  const [license, setLicense] = useState<LicenseStatusView>({
    authorized: false,
    machineCode: "读取中...",
    holderName: null,
    holderPhone: null,
    isPermanent: false,
    expiresAt: null,
    daysRemaining: null,
    machineBound: false,
    expiredMessage: null,
  });
  const [proxies, setProxies] = useState<ProxyView[]>([]);
  const [activeProxyId, setActiveProxyId] = useState<string | null>(null);
  const [settings, setSettings] = useState<AppSettings>({
    customBrowserPath: null,
    safeModeEnabled: true,
    watchdogIntervalSec: 45,
    autoStartEnabled: false,
  });
  const [browserEnvs, setBrowserEnvs] = useState<BrowserProfileEnv[]>([
    { id: "default", name: "默认环境" },
  ]);
  const [activeBrowserEnvId, setActiveBrowserEnvId] =
    useState<string>("default");
  const [browserState, setBrowserState] =
    useState<BrowserLifecycleState>("idle");
  const [runningProxyId, setRunningProxyId] = useState<string | null>(null);
  const [forwarderState, setForwarderState] = useState<ForwarderStateSnapshot>({
    status: "stopped",
  });
  const [circuitBreaker, setCircuitBreaker] = useState<CircuitBreakerSnapshot>({
    locked: false,
    reason: null,
    tripKind: null,
    triggeredAt: null,
    lastCheckAt: null,
    monitoringActive: false,
  });

  const [report, setReport] = useState<CheckReport | null>(null);
  const [checking, setChecking] = useState(false);
  const [launchingBrowser, setLaunchingBrowser] = useState(false);
  const [topError, setTopError] = useState<HumanizedError | null>(null);
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const [backupRecoveredNotice, setBackupRecoveredNotice] = useState(false);

  // CLI 工作目录可选输入
  const [cliWorkdir, setCliWorkdir] = useState("");
  const [toolBusy, setToolBusy] = useState<"cli" | "desktop" | null>(null);

  // 弹窗状态
  const [proxyModalMode, setProxyModalMode] = useState<
    "closed" | "list" | "create"
  >("closed");
  const [showLogModal, setShowLogModal] = useState(false);
  const [showResetModal, setShowResetModal] = useState(false);
  const [showSettingsModal, setShowSettingsModal] = useState(false);
  const [showCreateEnvModal, setShowCreateEnvModal] = useState(false);
  const [showCloseProtectModal, setShowCloseProtectModal] = useState(false);
  const [activeWatchdogAlert, setActiveWatchdogAlert] =
    useState<WatchdogAlertPayload | null>(null);
  const [riskModalState, setRiskModalState] = useState<{
    mode: "non_critical_warn" | "force_bypass";
    warnings: CheckItemResult[];
  } | null>(null);

  // 底部巡检秒数计时显示
  const [lastCheckEpochMs, setLastCheckEpochMs] = useState<number | null>(null);
  const [nowEpochMs, setNowEpochMs] = useState<number>(() => Date.now());
  const didBootRef = useRef(false);

  const showToast = useCallback((msg: string) => {
    setToastMessage(msg);
    setTimeout(() => {
      setToastMessage((cur) => (cur === msg ? null : cur));
    }, 3500);
  }, []);

  const triggerChecks = useCallback(async () => {
    setChecking(true);
    setTopError(null);
    try {
      const rep = await api.runChecks();
      setReport(rep);
    } catch (err) {
      const norm = normalizeError(err);
      if (norm.code !== "CHECK_CANCELLED") {
        setTopError(norm);
      }
    } finally {
      setChecking(false);
    }
  }, []);

  const refreshFullState = useCallback(async () => {
    const st = await api.getAppState();
    setLicense(st.license);
    setProxies(st.proxies);
    setActiveProxyId(st.activeProxyId);
    setSettings(st.settings);
    setBrowserEnvs(st.browserEnvs);
    setActiveBrowserEnvId(st.activeBrowserEnvId);
    setBrowserState(st.browserState);
    setRunningProxyId(st.runningProxyId);
    setForwarderState(st.forwarderState);
    setCircuitBreaker(st.circuitBreaker);
    if (st.latestReport) {
      setReport(st.latestReport);
    }
    if (st.recoveredFromBackup) {
      setBackupRecoveredNotice(true);
    }
    return st;
  }, []);

  // 初始化订阅后端实时事件与首屏状态加载
  useEffect(() => {
    const unlisteners: Array<() => void> = [];

    const setup = async () => {
      unlisteners.push(
        await events.onCheckProgress((rep) => {
          setReport(rep);
          setChecking(rep.isRunning);
        }),
      );
      unlisteners.push(
        await events.onBrowserState((st) => {
          setBrowserState(st);
          if (st === "idle" || st === "exited") {
            setRunningProxyId(null);
          } else if (st === "running") {
            void api.getAppState().then((full) => {
              setRunningProxyId(full.runningProxyId);
            });
          }
        }),
      );
      unlisteners.push(
        await events.onForwarderState((snap) => {
          setForwarderState(snap);
        }),
      );
      unlisteners.push(
        await events.onCircuitBreakerState((cb) => {
          setCircuitBreaker(cb);
          if (cb.lastCheckAt) {
            setLastCheckEpochMs(Date.now());
          }
        }),
      );
      unlisteners.push(
        await events.onWatchdogAlert((alert) => {
          setActiveWatchdogAlert(alert);
        }),
      );
      unlisteners.push(
        await events.onWindowCloseRequested(() => {
          setShowCloseProtectModal(true);
        }),
      );
      unlisteners.push(
        await events.onLicenseState((lic) => {
          setLicense(lic);
        }),
      );

      const initialState = await refreshFullState();
      setBootLoaded(true);
      // 仅在已通过授权且存在有效代理配置时启动自动跑一次检测
      if (
        !didBootRef.current &&
        initialState.license.authorized &&
        initialState.activeProxyId &&
        initialState.proxies.length > 0
      ) {
        didBootRef.current = true;
        void triggerChecks();
      } else {
        didBootRef.current = true;
      }
    };

    void setup();

    const timer = window.setInterval(() => {
      setNowEpochMs(Date.now());
    }, 1000);

    return () => {
      window.clearInterval(timer);
      unlisteners.forEach((fn) => fn());
    };
  }, [refreshFullState, triggerChecks]);

  const activeProxy = useMemo(
    () => proxies.find((p) => p.id === activeProxyId) ?? null,
    [proxies, activeProxyId],
  );

  // 当前激活代理匹配的检测报告
  const matchedReport = useMemo(() => {
    if (!report || !activeProxyId) return null;
    return report.proxyId === activeProxyId ? report : null;
  }, [report, activeProxyId]);

  const displayItems = matchedReport?.items ?? DEFAULT_FIVE_ITEMS;

  // 是否已知当前激活代理的关键项（01、02、04）存在红灯失败
  const hasKnownCriticalRed = useMemo(() => {
    if (!matchedReport || matchedReport.isRunning) return false;
    return matchedReport.items.some(
      (item) => item.critical && item.status === "red",
    );
  }, [matchedReport]);

  // 收集当前报告中出现错误/警告的检测项，集中在五盏灯下方展示友好报错与折叠详情
  const itemIssues = useMemo(
    () =>
      displayItems.filter(
        (i) => (i.status === "red" || i.status === "yellow") && i.error,
      ),
    [displayItems],
  );

  const handleQuickSwitchProxy = async (newId: string) => {
    if (!newId || newId === activeProxyId) return;
    setTopError(null);
    try {
      await api.setActiveProxy(newId);
      setActiveProxyId(newId);
      setReport(null);
      await triggerChecks();
    } catch (err) {
      setTopError(normalizeError(err));
    }
  };

  const handleToggleSafeMode = async (enabled: boolean) => {
    setTopError(null);
    try {
      const saved = await api.updateSettings({
        ...settings,
        safeModeEnabled: enabled,
      });
      setSettings(saved);
      showToast(
        enabled
          ? "已开启安全模式（泄露与掉线自动熔断保护）"
          : "已关闭安全模式（浏览器运行期间将不执行自动熔断）",
      );
    } catch (err) {
      setTopError(normalizeError(err));
    }
  };

  const handleSwitchBrowserEnv = async (envId: string) => {
    if (!envId || envId === activeBrowserEnvId) return;
    setTopError(null);
    try {
      const res = await api.setActiveBrowserEnv(envId);
      setBrowserEnvs(res.browserEnvs);
      setActiveBrowserEnvId(res.activeBrowserEnvId);
      const envName =
        res.browserEnvs.find((e) => e.id === res.activeBrowserEnvId)?.name ??
        "默认环境";
      showToast(`已切换至独立浏览器环境：${envName}`);
    } catch (err) {
      setTopError(normalizeError(err));
    }
  };

  const executeLaunchBrowser = async (
    force: boolean,
    allowWarnings?: boolean,
  ) => {
    setLaunchingBrowser(true);
    setTopError(null);
    try {
      const outcome = await api.launchBrowser(force, allowWarnings);
      if (outcome.outcome === "launched") {
        const bName =
          outcome.browser.kind === "brave"
            ? "Brave"
            : outcome.browser.kind === "chrome"
              ? "Chrome"
              : "自定义浏览器";
        const curEnvName =
          browserEnvs.find((e) => e.id === activeBrowserEnvId)?.name ??
          "默认环境";
        showToast(
          `已安全启动 ${bName} · ${curEnvName}（本地转发端口 127.0.0.1:${outcome.forwarderPort}）`,
        );
        await refreshFullState();
      } else if (outcome.outcome === "needsWarningConfirm") {
        setReport(outcome.report);
        setRiskModalState({
          mode: "non_critical_warn",
          warnings: outcome.warnings,
        });
      } else if (outcome.outcome === "blocked") {
        if (outcome.report) setReport(outcome.report);
        setTopError(outcome.reason);
      }
    } catch (err) {
      setTopError(normalizeError(err));
    } finally {
      setLaunchingBrowser(false);
    }
  };

  const handleCloseBrowser = async () => {
    setTopError(null);
    try {
      await api.closeBrowser();
      showToast("已安全终止浏览器进程树并释放本地转发端口");
      await refreshFullState();
    } catch (err) {
      setTopError(normalizeError(err));
    }
  };

  const handleLaunchCli = async () => {
    setToolBusy("cli");
    setTopError(null);
    try {
      const msg = await api.launchClaudeCode(cliWorkdir);
      showToast(msg);
      await refreshFullState();
    } catch (err) {
      setTopError(normalizeError(err));
    } finally {
      setToolBusy(null);
    }
  };

  const handleLaunchDesktop = async () => {
    setToolBusy("desktop");
    setTopError(null);
    try {
      const msg = await api.launchClaudeDesktop();
      showToast(msg);
      await refreshFullState();
    } catch (err) {
      setTopError(normalizeError(err));
    } finally {
      setToolBusy(null);
    }
  };

  // 计算主启动按钮禁用状态与文案（严格对应需求文档 4.4 & 12.8）
  const browserBtnConfig = useMemo(() => {
    if (browserState === "running") {
      return {
        disabled: false,
        isStopAction: true,
        label: "关闭安全浏览器（隔离保护运行中）",
        subHint:
          "点击将精准终止安全浏览器隔离进程树并立即释放本地转发端口",
      };
    }
    if (circuitBreaker.locked) {
      return {
        disabled: true,
        isStopAction: false,
        label: "安全熔断已触发 · 已锁定启动",
        subHint: "安全熔断已触发，请先点击上方【重新检测】通过后再启动",
      };
    }
    if (!activeProxy) {
      return {
        disabled: true,
        isStopAction: false,
        label: "启动安全浏览器",
        subHint: "请先添加并保存真实代理配置",
      };
    }
    if (checking || launchingBrowser || browserState === "launching") {
      return {
        disabled: true,
        isStopAction: false,
        label: launchingBrowser
          ? "正在执行启动前安全预检..."
          : "正在执行五项检测...",
        subHint: "请等待检测完成后启动",
      };
    }
    if (hasKnownCriticalRed) {
      return {
        disabled: true,
        isStopAction: false,
        label: "关键检测项未通过 · 禁止直连启动",
        subHint: "关键项（01/02/04）存在红灯阻断，请修复代理后点击【重新检测】",
      };
    }
    return {
      disabled: false,
      isStopAction: false,
      label: "启动安全浏览器访问 Claude",
      subHint:
        "自动探测 Brave → Chrome · 出口时区/语言自动对齐 · 禁用 QUIC / WebRTC / 本地 DNS",
    };
  }, [
    browserState,
    circuitBreaker.locked,
    activeProxy,
    checking,
    launchingBrowser,
    hasKnownCriticalRed,
  ]);

  // 底部巡检状态文案
  const watchdogFooterText = useMemo(() => {
    if (circuitBreaker.locked) {
      return `🚨 安全熔断锁定中（触发于 ${circuitBreaker.triggeredAt ?? "刚才"}）`;
    }
    if (!settings.safeModeEnabled) {
      return "安全模式：已关闭（建议开启以防掉线直连泄露）";
    }
    if (circuitBreaker.monitoringActive && browserState === "running") {
      const secAgo =
        lastCheckEpochMs !== null
          ? Math.max(0, Math.floor((nowEpochMs - lastCheckEpochMs) / 1000))
          : null;
      const agoStr =
        secAgo !== null
          ? `${secAgo} 秒前`
          : (circuitBreaker.lastCheckAt ?? "刚刚");
      return `🛡️ 安全巡检正常 · 上次检测 ${agoStr}（每 ${settings.watchdogIntervalSec} 秒）`;
    }
    return `安全模式已就绪（每 ${settings.watchdogIntervalSec} 秒巡检 · 随安全浏览器自动激活）`;
  }, [
    circuitBreaker,
    settings.safeModeEnabled,
    settings.watchdogIntervalSec,
    browserState,
    lastCheckEpochMs,
    nowEpochMs,
  ]);

  // 底部转发器状态文案
  const forwarderFooterText = useMemo(() => {
    if (forwarderState.status === "running") {
      return `🟢 本地转发器运行中 127.0.0.1:${forwarderState.port} · 当前活跃连接 ${forwarderState.activeConnections}`;
    }
    if (forwarderState.status === "tripped") {
      return "🔴 本地转发器：已紧急熔断断流";
    }
    return "⚪ 本地转发器：已停止（无引用时自动释放端口）";
  }, [forwarderState]);

  const handleSwitchLicense = async () => {
    setTopError(null);
    try {
      const nextLic = await api.deactivateLicense();
      setLicense(nextLic);
    } catch (err) {
      setTopError(normalizeError(err));
    }
  };

  if (!bootLoaded) {
    return (
      <div className="auth-gate-screen">
        <div className="muted-hint">正在初始化安全引擎...</div>
      </div>
    );
  }

  if (!license.authorized) {
    return (
      <LicenseGateView
        license={license}
        existingActiveProxy={activeProxy}
        onActivated={async (hasProxy) => {
          const st = await refreshFullState();
          if (hasProxy && st.activeProxyId) {
            void triggerChecks();
          }
        }}
      />
    );
  }

  return (
    <div className="app-layout">
      {/* 1. 顶部工具栏 */}
      <header className="header-bar">
        <div className="brand-area">
          <div className="shield-logo">🛡️</div>
          <div className="brand-text">
            <h1 className="brand-title">Claude安全客户端</h1>
            <span className="brand-ver">独立环境隔离 · 代理链路守护</span>
          </div>
        </div>

        <div className="header-controls">
          <div className="proxy-selector-group">
            <select
              className="proxy-select"
              value={activeProxyId ?? ""}
              onChange={(e) => void handleQuickSwitchProxy(e.target.value)}
              disabled={proxies.length === 0}
            >
              {proxies.length === 0 ? (
                <option value="">未配置代理节点</option>
              ) : (
                proxies.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name} ({p.host}:{p.port})
                  </option>
                ))
              )}
            </select>
            <button
              type="button"
              className="btn btn-sm btn-secondary"
              onClick={() =>
                setProxyModalMode(proxies.length === 0 ? "create" : "list")
              }
            >
              代理管理
            </button>
          </div>

          <label
            className={`safe-mode-pill ${settings.safeModeEnabled ? "on" : "off"}`}
            title="开启后后台持续监测出口 IP 与 DNS，异常掉线或泄露时秒级断流并关闭安全浏览器"
          >
            <input
              type="checkbox"
              checked={settings.safeModeEnabled}
              onChange={(e) => void handleToggleSafeMode(e.target.checked)}
            />
            <span className="pill-dot" />
            <span>安全模式{settings.safeModeEnabled ? "已开启" : "已关闭"}</span>
          </label>

          <div className="nav-icon-btns">
            <div
              className="license-user-pill"
              title={`授权用户：${license.holderName ?? ""} (${license.holderPhone ?? ""})${
                license.isPermanent
                  ? " · 永久有效"
                  : ` · 到期日：${license.expiresAt ?? "-"}`
              }`}
            >
              <span>🔑 {license.holderName}</span>
              <span
                className={
                  !license.isPermanent &&
                  license.daysRemaining !== null &&
                  license.daysRemaining <= 3
                    ? "license-days-soon"
                    : undefined
                }
              >
                ·{" "}
                {license.isPermanent
                  ? "永久"
                  : license.daysRemaining !== null &&
                      license.daysRemaining !== undefined
                    ? `剩余 ${Math.max(0, license.daysRemaining)} 天`
                    : `至 ${license.expiresAt}`}
              </span>
              <button
                type="button"
                className="license-switch-link"
                onClick={() => void handleSwitchLicense()}
              >
                切换
              </button>
            </div>
            <button
              type="button"
              className="btn btn-sm btn-ghost"
              onClick={() => setShowSettingsModal(true)}
            >
              设置
            </button>
            <button
              type="button"
              className="btn btn-sm btn-ghost"
              onClick={() => setShowLogModal(true)}
            >
              日志
            </button>
            <button
              type="button"
              className="btn btn-sm btn-ghost"
              onClick={() => setShowResetModal(true)}
            >
              重置环境
            </button>
          </div>
        </div>
      </header>

      {/* 主体内容滚动区 */}
      <main className="main-scroll">
        {/* 2. 条件置顶：安全熔断红色锁定横幅（需求文档 9.2） */}
        {circuitBreaker.locked && (
          <section className="circuit-locked-banner">
            <div className="locked-banner-left">
              <div className="locked-badge">🚨 安全自动熔断锁定态</div>
              <div className="locked-desc">
                {circuitBreaker.reason ??
                  "检测到代理连接断开或潜在泄露，已强制关闭安全浏览器并切断转发器流量。请确认代理恢复后点击右侧【重新检测】解锁。"}
              </div>
            </div>
            <button
              type="button"
              className="btn btn-danger-solid"
              disabled={checking || !activeProxy}
              onClick={() => void triggerChecks()}
            >
              {checking ? "正在重检..." : "立即重新检测"}
            </button>
          </section>
        )}

        {/* 配置文件备份恢复提示 */}
        {backupRecoveredNotice && (
          <div className="info-banner">
            <span>
              提示：检测到主配置文件损坏，系统已自动从上一次有效备份 (config.json.bak) 恢复数据。
            </span>
            <button
              type="button"
              className="btn-icon-close"
              onClick={() => setBackupRecoveredNotice(false)}
            >
              ×
            </button>
          </div>
        )}

        {/* Toast 轻提示 */}
        {toastMessage && <div className="toast-banner">✓ {toastMessage}</div>}

        {/* 顶层操作报错横幅 */}
        {topError && (
          <ErrorBanner
            error={topError}
            onDismiss={() => setTopError(null)}
          />
        )}

        {/* 3. 核心检测区：五盏灯仪表盘（继承 v1 经典布局） */}
        <section className="panel-card">
          <div className="panel-head">
            <div>
              <h2 className="panel-title">代理环境五项安全检测</h2>
              <div className="summary-metrics">
                {!activeProxy ? (
                  <span className="metric-muted">
                    请先添加并保存真实 SOCKS5 代理配置
                  </span>
                ) : (
                  <>
                    <span className="metric-chip">
                      出口 IP：
                      <strong>{matchedReport?.exitIp ?? "待获取"}</strong>
                    </span>
                    <span className="metric-chip">
                      归属国家：
                      <strong>
                        {matchedReport?.countryDisplay ?? "待获取"}
                      </strong>
                    </span>
                    {matchedReport?.isp && (
                      <span className="metric-chip">
                        运营商：<strong>{matchedReport.isp}</strong>
                      </span>
                    )}
                    <span className="metric-chip">
                      风险分：
                      <strong>
                        {matchedReport?.riskScore !== null &&
                        matchedReport?.riskScore !== undefined
                          ? `${matchedReport.riskScore} / 100`
                          : "—"}
                      </strong>
                    </span>
                  </>
                )}
              </div>
            </div>

            <div className="btn-row">
              {checking ? (
                <button
                  type="button"
                  className="btn btn-secondary btn-recheck"
                  onClick={() => void api.cancelChecks()}
                >
                  取消检测
                </button>
              ) : (
                <button
                  type="button"
                  className="btn btn-secondary btn-recheck"
                  disabled={!activeProxy}
                  onClick={() => void triggerChecks()}
                >
                  重新检测
                </button>
              )}
            </div>
          </div>

          {!activeProxy ? (
            <div className="unconfigured-guide">
              <p>尚未配置上游 SOCKS5 代理，请先添加并保存真实代理配置。</p>
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => setProxyModalMode("create")}
              >
                + 添加 SOCKS5 代理配置
              </button>
            </div>
          ) : (
            <>
              <div className="five-lights-grid">
                {displayItems.map((item) => (
                  <div
                    key={item.id}
                    className={`light-card status-${item.status}`}
                  >
                    <div className="light-card-top">
                      <span className="light-index">0{item.index}</span>
                      <span
                        className={`critical-tag ${item.critical ? "crit" : "warn"}`}
                      >
                        {item.critical ? "关键阻断" : "风险提示"}
                      </span>
                    </div>

                    <div className="light-lamp-row">
                      <span className={`lamp-orb ${item.status}`} />
                      <span className="light-name">{item.title}</span>
                    </div>

                    <div className="light-status-badge">
                      {statusLabelText(item.status)}
                      {item.latencyMs !== null ? ` · ${item.latencyMs}ms` : ""}
                    </div>

                    <div className="light-summary" title={item.summary}>
                      {item.summary}
                    </div>
                  </div>
                ))}
              </div>

              {itemIssues.length > 0 && (
                <div className="issues-stack">
                  {itemIssues.map((it) =>
                    it.error ? (
                      <ErrorBanner
                        key={it.id}
                        error={{
                          code: it.error.code,
                          userMessage: `[0${it.index} ${it.title}] ${it.error.userMessage}`,
                          technicalDetail: it.error.technicalDetail,
                        }}
                        variant={it.status === "red" ? "danger" : "warning"}
                      />
                    ) : null,
                  )}
                </div>
              )}
            </>
          )}
        </section>

        {/* 4. 操作与启动控制区 */}
        <section className="launch-grid">
          <div className="panel-card launch-primary-card">
            <div className="launch-head">
              <div className="launch-head-top">
                <h3>安全隔离浏览器（推荐主入口）</h3>
                <select
                  className="env-select"
                  value={activeBrowserEnvId}
                  disabled={browserState === "running" || launchingBrowser}
                  title="切换不同 Claude 账号专属的浏览器隔离目录（Cookie 与本地缓存完全物理隔离）"
                  onChange={(e) => {
                    const val = e.target.value;
                    if (val === "__create_new__") {
                      setShowCreateEnvModal(true);
                    } else {
                      void handleSwitchBrowserEnv(val);
                    }
                  }}
                >
                  {browserEnvs.map((env) => (
                    <option key={env.id} value={env.id}>
                      {env.name}
                    </option>
                  ))}
                  <option value="__create_new__">+ 新建独立环境</option>
                </select>
              </div>
              <span className="muted-hint">{browserBtnConfig.subHint}</span>
            </div>

            <div className="primary-action-row">
              <button
                type="button"
                className={`btn btn-hero ${
                  browserBtnConfig.isStopAction
                    ? "btn-stop-browser"
                    : "btn-launch-browser"
                }`}
                disabled={browserBtnConfig.disabled}
                onClick={() => {
                  if (browserBtnConfig.isStopAction) {
                    void handleCloseBrowser();
                  } else {
                    void executeLaunchBrowser(false);
                  }
                }}
              >
                {browserBtnConfig.label}
              </button>
            </div>

            <div className="secondary-force-row">
              <span className="muted-hint">
                所有流量统一经本地回环转发器透传 · 不同代理登录态完全物理隔离
              </span>
              {!circuitBreaker.locked &&
                browserState !== "running" &&
                activeProxy && (
                  <button
                    type="button"
                    className="btn-link danger-link whitespace-nowrap"
                    disabled={launchingBrowser}
                    onClick={() =>
                      setRiskModalState({
                        mode: "force_bypass",
                        warnings: [],
                      })
                    }
                  >
                    忽略检测，强制启动
                  </button>
                )}
            </div>
          </div>

          <div className="panel-card launch-tools-card">
            <h3>扩展工具安全代理注入</h3>
            <div className="tool-block">
              <div className="tool-info">
                <strong>启动 Claude Code (CLI)</strong>
                <span>独立终端自动注入 HTTP/HTTPS_PROXY 环境变量</span>
              </div>
              <div className="tool-cli-controls">
                <input
                  type="text"
                  className="form-input form-input-sm"
                  placeholder="可选工作目录（留空默认用户主目录）"
                  value={cliWorkdir}
                  onChange={(e) => setCliWorkdir(e.target.value)}
                />
                <button
                  type="button"
                  className="btn btn-sm btn-secondary tool-action-btn"
                  disabled={
                    !activeProxy ||
                    circuitBreaker.locked ||
                    toolBusy === "cli"
                  }
                  onClick={() => void handleLaunchCli()}
                >
                  {toolBusy === "cli" ? "启动中..." : "启动 CLI"}
                </button>
              </div>
            </div>

            <div className="tool-divider" />

            <div className="tool-block row-between">
              <div className="tool-info">
                <strong>启动 Claude 桌面客户端</strong>
                <span>
                  {IS_MAC
                    ? "自动探测 /Applications/Claude.app · 注入安全代理转发参数"
                    : "兼容官方 MSIX 与独立桌面版 · 自动注入安全代理转发参数"}
                </span>
              </div>
              <button
                type="button"
                className="btn btn-sm btn-secondary tool-action-btn"
                disabled={
                  !activeProxy ||
                  circuitBreaker.locked ||
                  toolBusy === "desktop"
                }
                onClick={() => void handleLaunchDesktop()}
              >
                {toolBusy === "desktop" ? "启动中..." : "启动桌面端"}
              </button>
            </div>
          </div>
        </section>
      </main>

      {/* 5. 底部常驻实时状态栏（需求文档 6.3） */}
      <footer className="status-footer">
        <div className="footer-item">{forwarderFooterText}</div>
        <div className="footer-item">{watchdogFooterText}</div>
      </footer>

      {/* 6. 弹窗层 */}
      {proxyModalMode !== "closed" && (
        <ProxyManagerModal
          proxies={proxies}
          activeProxyId={activeProxyId}
          runningProxyId={runningProxyId}
          initialMode={proxyModalMode === "create" ? "create" : "list"}
          onClose={() => setProxyModalMode("closed")}
          onChanged={async (shouldRunCheck) => {
            const st = await refreshFullState();
            if (shouldRunCheck && st.activeProxyId) {
              void triggerChecks();
            } else if (!st.activeProxyId) {
              setReport(null);
            }
          }}
        />
      )}

      {showLogModal && (
        <LogViewerModal onClose={() => setShowLogModal(false)} />
      )}

      {showResetModal && (
        <ResetEnvModal
          browserRunning={browserState === "running"}
          onClose={() => setShowResetModal(false)}
          onResetDone={async (msg) => {
            showToast(msg);
            const st = await refreshFullState();
            if (!st.activeProxyId) {
              setReport(null);
            }
          }}
        />
      )}

      {showSettingsModal && (
        <SettingsModal
          settings={settings}
          onClose={() => setShowSettingsModal(false)}
          onSaved={(newSettings) => {
            setSettings(newSettings);
            showToast("安全与浏览器设置已保存生效");
          }}
        />
      )}

      {showCreateEnvModal && (
        <CreateBrowserEnvModal
          suggestedName={`环境${browserEnvs.length + 1}`}
          onClose={() => setShowCreateEnvModal(false)}
          onCreated={(envs, activeId, createdName) => {
            setBrowserEnvs(envs);
            setActiveBrowserEnvId(activeId);
            showToast(`已创建并切换至独立环境：${createdName}`);
          }}
        />
      )}

      {riskModalState && (
        <RiskConfirmModal
          mode={riskModalState.mode}
          warnings={riskModalState.warnings}
          onCancel={() => setRiskModalState(null)}
          onConfirm={() => {
            const mode = riskModalState.mode;
            setRiskModalState(null);
            if (mode === "non_critical_warn") {
              void executeLaunchBrowser(false, true);
            } else {
              void executeLaunchBrowser(true);
            }
          }}
        />
      )}

      {showCloseProtectModal && (
        <WindowCloseProtectionModal
          onCancel={() => setShowCloseProtectModal(false)}
          onMinimizeToTray={() => {
            setShowCloseProtectModal(false);
            void api.hideToTray();
          }}
          onConfirmExit={() => {
            setShowCloseProtectModal(false);
            void api.confirmExitApp();
          }}
        />
      )}

      {activeWatchdogAlert && (
        <WatchdogAlertModal
          alert={activeWatchdogAlert}
          onDismiss={() => setActiveWatchdogAlert(null)}
          onRecheckNow={() => void triggerChecks()}
        />
      )}
    </div>
  );
}
