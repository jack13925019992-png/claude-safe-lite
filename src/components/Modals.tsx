import { useEffect, useMemo, useState } from "react";
import { api, normalizeError } from "../api";
import type {
  AppSettings,
  CheckItemResult,
  HumanizedError,
  LogKind,
  ProxyView,
  ResetEnvOptions,
  SaveProxyInput,
  WatchdogAlertPayload,
} from "../types";
import { ErrorBanner } from "./ErrorBanner";

const IS_MAC =
  typeof navigator !== "undefined" &&
  /Mac|iPod|iPhone|iPad/i.test(navigator.userAgent);

// ============================================================================
// 1. 代理配置管理与编辑弹窗（需求文档 5.3 & 6.1）
// ============================================================================

interface ProxyManagerModalProps {
  proxies: ProxyView[];
  activeProxyId: string | null;
  runningProxyId: string | null;
  initialMode?: "list" | "create";
  onClose: () => void;
  onChanged: (shouldRunCheck: boolean) => Promise<void>;
}

function validateHostClientSide(raw: string): string | null {
  const host = raw.trim();
  if (!host) return "代理主机地址不能为空";
  if (host.includes("://") || host.includes("/") || /\s/.test(host)) {
    return "主机地址不应包含协议头 (socks5://)、斜杠或空格";
  }
  if (host.startsWith("[") && host.endsWith("]")) {
    const inner = host.slice(1, -1);
    if (!inner.includes(":")) return "方括号内应为合法 IPv6 地址";
    return null;
  }
  if (host.includes(":")) {
    // 简单校验 IPv6 字符集
    if (!/^[0-9a-fA-F:]+$/.test(host)) {
      return "IPv6 地址包含非法字符（注意端口请填在右侧端口框）";
    }
    return null;
  }
  if (/^[0-9.]+$/.test(host)) {
    const parts = host.split(".");
    if (
      parts.length !== 4 ||
      parts.some((p) => p === "" || Number(p) < 0 || Number(p) > 255 || String(Number(p)) !== p)
    ) {
      return "IPv4 地址格式不合法（须为 4 段 0–255 数字）";
    }
    return null;
  }
  if (host.length > 253) return "域名总长度不能超过 253 个字符";
  const labels = host.split(".");
  if (
    labels.some(
      (l) =>
        !l ||
        l.length > 63 ||
        l.startsWith("-") ||
        l.endsWith("-") ||
        !/^[a-zA-Z0-9-]+$/.test(l),
    )
  ) {
    return "域名格式不合法";
  }
  return null;
}

export function ProxyManagerModal({
  proxies,
  activeProxyId,
  runningProxyId,
  initialMode = "list",
  onClose,
  onChanged,
}: ProxyManagerModalProps) {
  const [editingId, setEditingId] = useState<string | null>(null);
  const [isFormOpen, setIsFormOpen] = useState<boolean>(
    initialMode === "create" || proxies.length === 0,
  );

  // 表单字段：新建时一律留空，127.0.0.1 / 1080 仅作灰色 placeholder！
  const [name, setName] = useState("");
  const [host, setHost] = useState("");
  const [portText, setPortText] = useState("");
  const [authEnabled, setAuthEnabled] = useState(true);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [hasSavedPassword, setHasSavedPassword] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  const [quickPaste, setQuickPaste] = useState("");
  const [pasteNotice, setPasteNotice] = useState<string | null>(null);
  const [modalError, setModalError] = useState<HumanizedError | null>(null);
  const [testResult, setTestResult] = useState<CheckItemResult | null>(null);
  const [testing, setTesting] = useState(false);
  const [saving, setSaving] = useState(false);

  const openCreateForm = () => {
    setEditingId(null);
    setName("");
    setHost("");
    setPortText("");
    setAuthEnabled(true);
    setUsername("");
    setPassword("");
    setHasSavedPassword(false);
    setShowPassword(false);
    setQuickPaste("");
    setPasteNotice(null);
    setModalError(null);
    setTestResult(null);
    setIsFormOpen(true);
  };

  const openEditForm = (p: ProxyView) => {
    setEditingId(p.id);
    setName(p.name);
    setHost(p.host);
    setPortText(String(p.port));
    setAuthEnabled(p.authEnabled);
    setUsername(p.username);
    setPassword(""); // 零明文持有：编辑时留空表示沿用已加密旧密码
    setHasSavedPassword(p.hasPassword);
    setShowPassword(false);
    setQuickPaste("");
    setPasteNotice(null);
    setModalError(null);
    setTestResult(null);
    setIsFormOpen(true);
  };

  // 实时表单校验
  const validationMessage = useMemo(() => {
    if (!isFormOpen) return null;
    if (!name.trim()) return "请填写配置名称（如：美国静态住宅 01）";
    const hostErr = validateHostClientSide(host);
    if (hostErr) return hostErr;
    const trimmedPort = portText.trim();
    if (!trimmedPort || !/^\d+$/.test(trimmedPort)) {
      return "端口号必须为 1–65535 之间的整数";
    }
    const portNum = Number(trimmedPort);
    if (portNum < 1 || portNum > 65535) {
      return "端口号必须在 1–65535 范围内";
    }
    if (authEnabled) {
      if (!username.trim()) return "开启认证后代理用户名不能为空";
      if (new TextEncoder().encode(username.trim()).length > 255) {
        return "用户名 UTF-8 长度不能超过 255 字节";
      }
      if (!editingId || !hasSavedPassword) {
        if (!password) return "新建带认证代理时密码不能为空";
      }
      if (password && new TextEncoder().encode(password).length > 255) {
        return "密码 UTF-8 长度不能超过 255 字节";
      }
    }
    return null;
  }, [isFormOpen, name, host, portText, authEnabled, username, password, editingId, hasSavedPassword]);

  // 用于测试连接（允许名称暂未填时也能快速测连通）
  const canTestConnection = useMemo(() => {
    if (validateHostClientSide(host)) return false;
    const p = Number(portText.trim());
    if (!/^\d+$/.test(portText.trim()) || p < 1 || p > 65535) return false;
    if (authEnabled) {
      if (!username.trim()) return false;
      if (!password && (!editingId || !hasSavedPassword)) return false;
    }
    return true;
  }, [host, portText, authEnabled, username, password, editingId, hasSavedPassword]);

  const handleQuickParse = async () => {
    setModalError(null);
    setPasteNotice(null);
    if (!quickPaste.trim()) return;
    try {
      const parsed = await api.parseProxyText(quickPaste);
      setHost(parsed.host);
      setPortText(String(parsed.port));
      setAuthEnabled(parsed.authEnabled);
      setUsername(parsed.username);
      setPassword(parsed.password);
      if (!name.trim()) {
        setName(`SOCKS5 节点 (${parsed.host})`);
      }
      setPasteNotice("已自动解析并回填代理信息，请确认后点击保存");
      setTestResult(null);
    } catch (err) {
      setModalError(normalizeError(err));
    }
  };

  const buildPayload = (): SaveProxyInput => ({
    id: editingId,
    name: name.trim() || "临时测试节点",
    host: host.trim(),
    port: Number(portText.trim()),
    authEnabled,
    username: username.trim(),
    password: password ? password : null,
  });

  const handleTestConnection = async () => {
    setTesting(true);
    setModalError(null);
    setTestResult(null);
    try {
      const res = await api.testProxyConnection(buildPayload());
      setTestResult(res);
    } catch (err) {
      setModalError(normalizeError(err));
    } finally {
      setTesting(false);
    }
  };

  const handleSave = async () => {
    if (validationMessage) return;
    setSaving(true);
    setModalError(null);
    try {
      const saved = await api.saveProxy(buildPayload());
      const wasActiveOrFirst =
        proxies.length === 0 || saved.id === activeProxyId;
      await onChanged(wasActiveOrFirst);
      setIsFormOpen(false);
    } catch (err) {
      setModalError(normalizeError(err));
    } finally {
      setSaving(false);
    }
  };

  const handleActivate = async (id: string) => {
    setModalError(null);
    try {
      await api.setActiveProxy(id);
      await onChanged(true);
    } catch (err) {
      setModalError(normalizeError(err));
    }
  };

  const handleDuplicate = async (id: string) => {
    setModalError(null);
    try {
      await api.duplicateProxy(id);
      await onChanged(false);
    } catch (err) {
      setModalError(normalizeError(err));
    }
  };

  const handleDelete = async (p: ProxyView) => {
    setModalError(null);
    try {
      const wasActive = p.id === activeProxyId;
      const nextActive = await api.deleteProxy(p.id);
      await onChanged(wasActive && nextActive !== null);
    } catch (err) {
      setModalError(normalizeError(err));
    }
  };

  return (
    <div className="modal-backdrop">
      <div className="modal-card modal-lg">
        <div className="modal-header">
          <h3>
            {isFormOpen
              ? editingId
                ? "编辑 SOCKS5 代理配置"
                : "新建 SOCKS5 代理配置"
              : IS_MAC
                ? "多套代理配置管理 (本机硬件绑定加密存储)"
                : "多套代理配置管理 (DPAPI 加密存储)"}
          </h3>
          <button type="button" className="btn-icon-close" onClick={onClose}>
            ×
          </button>
        </div>

        <div className="modal-body">
          {modalError && (
            <ErrorBanner
              error={modalError}
              onDismiss={() => setModalError(null)}
            />
          )}

          {!isFormOpen ? (
            <div className="proxy-list-section">
              <div className="section-toolbar">
                <span className="muted-hint">
                  共 {proxies.length} 套配置 · 每套配置拥有独立浏览器隔离目录（Cookie 与登录态互不串号）
                </span>
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={openCreateForm}
                >
                  + 新增代理配置
                </button>
              </div>

              {proxies.length === 0 ? (
                <div className="empty-box">
                  <p>当前尚未保存任何代理配置。</p>
                  <button
                    type="button"
                    className="btn btn-primary"
                    onClick={openCreateForm}
                  >
                    立即添加第一套代理
                  </button>
                </div>
              ) : (
                <div className="proxy-table">
                  {proxies.map((p) => {
                    const isActive = p.id === activeProxyId;
                    const isRunning = p.id === runningProxyId;
                    return (
                      <div
                        key={p.id}
                        className={`proxy-row ${isActive ? "active" : ""}`}
                      >
                        <div className="proxy-row-info">
                          <div className="proxy-row-title">
                            <strong>{p.name}</strong>
                            {isActive && (
                              <span className="tag tag-green">当前激活</span>
                            )}
                            {isRunning && (
                              <span className="tag tag-blue">浏览器运行中</span>
                            )}
                            <span className="tag tag-outline">
                              {p.authEnabled ? "RFC1929 认证" : "无认证"}
                            </span>
                          </div>
                          <div className="proxy-row-sub">
                            socks5://{p.host}:{p.port}
                            {p.authEnabled && p.username
                              ? ` · 账号: ${p.username}`
                              : ""}
                          </div>
                        </div>
                        <div className="proxy-row-ops">
                          {!isActive && (
                            <button
                              type="button"
                              className="btn btn-sm btn-secondary"
                              onClick={() => void handleActivate(p.id)}
                            >
                              切换启用
                            </button>
                          )}
                          <button
                            type="button"
                            className="btn btn-sm btn-ghost"
                            onClick={() => openEditForm(p)}
                          >
                            编辑
                          </button>
                          <button
                            type="button"
                            className="btn btn-sm btn-ghost"
                            onClick={() => void handleDuplicate(p.id)}
                          >
                            复制
                          </button>
                          <button
                            type="button"
                            className="btn btn-sm btn-danger-ghost"
                            onClick={() => void handleDelete(p)}
                          >
                            删除
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          ) : (
            <div className="proxy-form">
              <div className="quick-paste-box">
                <label className="form-label">
                  快捷粘贴解析（支持 <code>host:port:user:pass</code> 或{" "}
                  <code>socks5://user:pass@host:port</code>，兼容特殊字符密码）
                </label>
                <div className="input-group">
                  <input
                    type="text"
                    className="form-input"
                    placeholder="粘贴完整代理串到此处一键解析..."
                    value={quickPaste}
                    onChange={(e) => setQuickPaste(e.target.value)}
                  />
                  <button
                    type="button"
                    className="btn btn-secondary"
                    onClick={() => void handleQuickParse()}
                  >
                    解析填入
                  </button>
                </div>
                {pasteNotice && (
                  <div className="success-hint">{pasteNotice}</div>
                )}
              </div>

              <div className="form-grid">
                <div className="form-field full-width">
                  <label className="form-label">配置名称 *</label>
                  <input
                    type="text"
                    className="form-input"
                    placeholder="例如：美国静态住宅 01"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                  />
                </div>

                <div className="form-field">
                  <label className="form-label">
                    SOCKS5 主机地址 (域名 / IPv4 / IPv6) *
                  </label>
                  <input
                    type="text"
                    className="form-input"
                    placeholder="127.0.0.1"
                    value={host}
                    onChange={(e) => {
                      setHost(e.target.value);
                      setTestResult(null);
                    }}
                  />
                </div>

                <div className="form-field">
                  <label className="form-label">端口 (1–65535) *</label>
                  <input
                    type="text"
                    inputMode="numeric"
                    className="form-input"
                    placeholder="1080"
                    value={portText}
                    onChange={(e) => {
                      setPortText(e.target.value);
                      setTestResult(null);
                    }}
                  />
                </div>
              </div>

              <div className="switch-row">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={authEnabled}
                    onChange={(e) => {
                      setAuthEnabled(e.target.checked);
                      setTestResult(null);
                    }}
                  />
                  <span>开启用户名 / 密码认证 (RFC 1929)</span>
                </label>
              </div>

              {authEnabled && (
                <div className="form-grid">
                  <div className="form-field">
                    <label className="form-label">代理用户名 *</label>
                    <input
                      type="text"
                      className="form-input"
                      placeholder="输入代理账号"
                      value={username}
                      onChange={(e) => {
                        setUsername(e.target.value);
                        setTestResult(null);
                      }}
                    />
                  </div>

                  <div className="form-field">
                    <label className="form-label">
                      代理密码 {editingId && hasSavedPassword ? "(留空保持原密码)" : "*"}
                    </label>
                    <div className="input-group">
                      <input
                        type={showPassword ? "text" : "password"}
                        className="form-input"
                        placeholder={
                          editingId && hasSavedPassword
                            ? "已加密保存，留空则保持不变"
                            : IS_MAC
                              ? "输入代理密码（采用本机硬件绑定 AEAD 加密）"
                              : "输入代理密码（采用 Windows DPAPI 加密）"
                        }
                        value={password}
                        onChange={(e) => {
                          setPassword(e.target.value);
                          setTestResult(null);
                        }}
                      />
                      <button
                        type="button"
                        className="btn btn-ghost"
                        onClick={() => setShowPassword((v) => !v)}
                      >
                        {showPassword ? "隐藏" : "显示"}
                      </button>
                    </div>
                  </div>
                </div>
              )}

              {validationMessage && (
                <div className="validation-tip">提示：{validationMessage}</div>
              )}

              {testResult && (
                <div className="inline-test-result">
                  {testResult.status === "green" ? (
                    <div className="test-pass-banner">
                      ✓ 代理连接测试通过：{testResult.summary}
                    </div>
                  ) : testResult.error ? (
                    <ErrorBanner error={testResult.error} />
                  ) : (
                    <div className="validation-tip">
                      连接未通过：{testResult.summary}
                    </div>
                  )}
                </div>
              )}

              <div className="modal-footer-split">
                <div>
                  {proxies.length > 0 && (
                    <button
                      type="button"
                      className="btn btn-ghost"
                      onClick={() => setIsFormOpen(false)}
                    >
                      ← 返回配置列表
                    </button>
                  )}
                </div>
                <div className="btn-row">
                  <button
                    type="button"
                    className="btn btn-secondary"
                    disabled={!canTestConnection || testing}
                    onClick={() => void handleTestConnection()}
                  >
                    {testing ? "正在测试握手..." : "测试连接"}
                  </button>
                  <button
                    type="button"
                    className="btn btn-primary"
                    disabled={Boolean(validationMessage) || saving}
                    onClick={() => void handleSave()}
                  >
                    {saving ? "加密保存中..." : "保存配置"}
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// 2. 三分类脱敏日志查看器（需求文档 5.4）
// ============================================================================

export function LogViewerModal({ onClose }: { onClose: () => void }) {
  const [kind, setKind] = useState<LogKind>("check");
  const [lines, setLines] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<HumanizedError | null>(null);

  const loadLogs = async (targetKind: LogKind) => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.readLog(targetKind, 500);
      setLines(data);
    } catch (err) {
      setError(normalizeError(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadLogs(kind);
  }, [kind]);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(lines.join("\n"));
      setNotice("已复制当前分类脱敏日志到剪贴板");
      setTimeout(() => setNotice(null), 2500);
    } catch {
      setNotice("复制失败，请使用导出功能保存文件");
    }
  };

  const handleCopyDiagnostics = async () => {
    setError(null);
    try {
      const reportText = await api.getDiagnosticReport();
      await navigator.clipboard.writeText(reportText);
      setNotice(
        "✓ 已复制脱敏诊断信息到剪贴板（节点密码、敏感代理地址与完整授权码均已 *** 脱敏）",
      );
      setTimeout(() => setNotice(null), 3500);
    } catch (err) {
      setError(normalizeError(err));
    }
  };

  const handleExport = async () => {
    setError(null);
    try {
      const path = await api.exportLog(kind);
      if (path) {
        setNotice(`已导出至: ${path}`);
      }
    } catch (err) {
      setError(normalizeError(err));
    }
  };

  const handleClear = async () => {
    setError(null);
    try {
      await api.clearLog(kind);
      setLines([]);
      setNotice("已清空当前分类日志");
    } catch (err) {
      setError(normalizeError(err));
    }
  };

  return (
    <div className="modal-backdrop">
      <div className="modal-card modal-lg">
        <div className="modal-header">
          <h3>系统分类日志（强制脱敏 · 最近 500 行）</h3>
          <button type="button" className="btn-icon-close" onClick={onClose}>
            ×
          </button>
        </div>

        <div className="modal-body">
          <div className="tabs-toolbar">
            <div className="tab-group">
              {(
                [
                  ["check", "检测日志 (check.log)"],
                  ["launch", "启动日志 (launch.log)"],
                  ["app", "应用日志 (app.log)"],
                ] as [LogKind, string][]
              ).map(([k, label]) => (
                <button
                  key={k}
                  type="button"
                  className={`tab-btn ${kind === k ? "active" : ""}`}
                  onClick={() => {
                    setNotice(null);
                    setKind(k);
                  }}
                >
                  {label}
                </button>
              ))}
            </div>

            <div className="btn-row">
              <button
                type="button"
                className="btn btn-sm btn-primary"
                onClick={() => void handleCopyDiagnostics()}
              >
                复制脱敏诊断信息
              </button>
              <button
                type="button"
                className="btn btn-sm btn-ghost"
                onClick={() => void loadLogs(kind)}
              >
                刷新
              </button>
              <button
                type="button"
                className="btn btn-sm btn-secondary"
                disabled={lines.length === 0}
                onClick={() => void handleCopy()}
              >
                一键复制
              </button>
              <button
                type="button"
                className="btn btn-sm btn-secondary"
                disabled={lines.length === 0}
                onClick={() => void handleExport()}
              >
                导出文件
              </button>
              <button
                type="button"
                className="btn btn-sm btn-danger-ghost"
                disabled={lines.length === 0}
                onClick={() => void handleClear()}
              >
                清空当前分类
              </button>
            </div>
          </div>

          {notice && <div className="success-hint">{notice}</div>}
          {error && (
            <ErrorBanner error={error} onDismiss={() => setError(null)} />
          )}

          <div className="log-console">
            {loading ? (
              <div className="log-empty">正在读取日志...</div>
            ) : lines.length === 0 ? (
              <div className="log-empty">当前分类暂无日志记录</div>
            ) : (
              lines.map((line, idx) => {
                const cls = line.includes("[ERROR]")
                  ? "log-line error"
                  : line.includes("[WARN]")
                    ? "log-line warn"
                    : "log-line";
                return (
                  <div key={idx} className={cls}>
                    {line}
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// 3. 重置环境弹窗（需求文档 5.5：默认勾选前两项，默认不勾选清除代理配置）
// ============================================================================

export function ResetEnvModal({
  browserRunning,
  onClose,
  onResetDone,
}: {
  browserRunning: boolean;
  onClose: () => void;
  onResetDone: (msg: string) => Promise<void>;
}) {
  const [options, setOptions] = useState<ResetEnvOptions>({
    cleanBrowserProfiles: true,
    cleanLogs: true,
    clearProxies: false,
    restoreDefaultSettings: false,
  });
  const [confirmStep, setConfirmStep] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<HumanizedError | null>(null);

  const anySelected =
    options.cleanBrowserProfiles ||
    options.cleanLogs ||
    options.clearProxies ||
    options.restoreDefaultSettings;

  const handleExecute = async () => {
    setBusy(true);
    setError(null);
    try {
      const res = await api.resetEnv(options);
      await onResetDone(res.message);
      onClose();
    } catch (err) {
      setError(normalizeError(err));
      setConfirmStep(false);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="modal-backdrop">
      <div className="modal-card">
        <div className="modal-header">
          <h3>重置运行环境</h3>
          <button type="button" className="btn-icon-close" onClick={onClose}>
            ×
          </button>
        </div>

        <div className="modal-body">
          {browserRunning && (
            <ErrorBanner
              error={{
                code: "BROWSER_ACTIVE",
                userMessage:
                  "安全浏览器正在运行中 → 请先关闭安全浏览器后再执行环境重置",
                technicalDetail: "",
              }}
            />
          )}
          {error && (
            <ErrorBanner error={error} onDismiss={() => setError(null)} />
          )}

          {!confirmStep ? (
            <>
              <div className="checklist-group">
                <label className="checkbox-card">
                  <input
                    type="checkbox"
                    checked={options.cleanBrowserProfiles}
                    onChange={(e) =>
                      setOptions((o) => ({
                        ...o,
                        cleanBrowserProfiles: e.target.checked,
                      }))
                    }
                  />
                  <div>
                    <div className="checkbox-title">清理全部浏览器配置目录</div>
                    <div className="checkbox-desc">
                      提示：将清除隔离缓存并退出所有代理下的 Claude 网页登录态
                    </div>
                  </div>
                </label>

                <label className="checkbox-card">
                  <input
                    type="checkbox"
                    checked={options.cleanLogs}
                    onChange={(e) =>
                      setOptions((o) => ({ ...o, cleanLogs: e.target.checked }))
                    }
                  />
                  <div>
                    <div className="checkbox-title">清理全部日志</div>
                    <div className="checkbox-desc">
                      清空检测日志、启动日志与应用日志及历史轮转分片
                    </div>
                  </div>
                </label>

                <label className="checkbox-card">
                  <input
                    type="checkbox"
                    checked={options.clearProxies}
                    onChange={(e) =>
                      setOptions((o) => ({
                        ...o,
                        clearProxies: e.target.checked,
                      }))
                    }
                  />
                  <div>
                    <div className="checkbox-title">
                      清除全部代理配置（谨慎勾选）
                    </div>
                    <div className="checkbox-desc">
                      永久移除已保存的所有 SOCKS5 代理节点信息
                    </div>
                  </div>
                </label>

                <label className="checkbox-card">
                  <input
                    type="checkbox"
                    checked={options.restoreDefaultSettings}
                    onChange={(e) =>
                      setOptions((o) => ({
                        ...o,
                        restoreDefaultSettings: e.target.checked,
                      }))
                    }
                  />
                  <div>
                    <div className="checkbox-title">恢复默认设置</div>
                    <div className="checkbox-desc">
                      恢复手动浏览器路径为空、开启安全模式、巡检间隔 45 秒
                    </div>
                  </div>
                </label>
              </div>

              <div className="modal-footer">
                <button type="button" className="btn btn-ghost" onClick={onClose}>
                  取消
                </button>
                <button
                  type="button"
                  className="btn btn-danger-solid"
                  disabled={!anySelected || browserRunning}
                  onClick={() => setConfirmStep(true)}
                >
                  下一步确认
                </button>
              </div>
            </>
          ) : (
            <div className="confirm-panel">
              <p className="confirm-warning-text">
                确定要立即执行所选的环境重置操作吗？此操作不可撤销。
              </p>
              <div className="modal-footer">
                <button
                  type="button"
                  className="btn btn-ghost"
                  onClick={() => setConfirmStep(false)}
                >
                  返回修改
                </button>
                <button
                  type="button"
                  className="btn btn-danger-solid"
                  disabled={busy || browserRunning}
                  onClick={() => void handleExecute()}
                >
                  {busy ? "正在清理重置..." : "确认立即重置"}
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// 4. 应用设置弹窗（安全模式周期 30/45/60s + 自定义浏览器路径）
// ============================================================================

export function SettingsModal({
  settings,
  onClose,
  onSaved,
}: {
  settings: AppSettings;
  onClose: () => void;
  onSaved: (s: AppSettings) => void;
}) {
  const [safeMode, setSafeMode] = useState(settings.safeModeEnabled);
  const [autoStart, setAutoStart] = useState(settings.autoStartEnabled);
  const [intervalSec, setIntervalSec] = useState(settings.watchdogIntervalSec);
  const [browserPath, setBrowserPath] = useState(
    settings.customBrowserPath ?? "",
  );
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<HumanizedError | null>(null);

  const handleSave = async () => {
    setSaving(true);
    setError(null);
    try {
      const updated = await api.updateSettings({
        safeModeEnabled: safeMode,
        autoStartEnabled: autoStart,
        watchdogIntervalSec: intervalSec,
        customBrowserPath: browserPath.trim() ? browserPath.trim() : null,
      });
      onSaved(updated);
      onClose();
    } catch (err) {
      setError(normalizeError(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="modal-backdrop">
      <div className="modal-card">
        <div className="modal-header">
          <h3>安全与浏览器设置</h3>
          <button type="button" className="btn-icon-close" onClick={onClose}>
            ×
          </button>
        </div>

        <div className="modal-body">
          {error && (
            <ErrorBanner error={error} onDismiss={() => setError(null)} />
          )}

          <div className="form-field">
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={safeMode}
                onChange={(e) => setSafeMode(e.target.checked)}
              />
              <span>启用安全模式（IP/DNS 泄露与掉线自动熔断保护，强烈推荐）</span>
            </label>
          </div>

          <div className="form-field" style={{ marginTop: 6 }}>
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={autoStart}
                onChange={(e) => setAutoStart(e.target.checked)}
              />
              <span>
                开机自动启动（
                {IS_MAC
                  ? "写入当前用户 LaunchAgents 启动项，免管理员密码"
                  : "写入当前用户 Windows 启动项，不触发管理员弹窗"}
                ）
              </span>
            </label>
          </div>

          <div className="form-field" style={{ marginTop: 14 }}>
            <label className="form-label">后台安全巡检周期</label>
            <div className="segmented-group">
              {[30, 45, 60].map((sec) => (
                <button
                  key={sec}
                  type="button"
                  className={`segment-btn ${intervalSec === sec ? "active" : ""}`}
                  onClick={() => setIntervalSec(sec)}
                >
                  {sec} 秒{sec === 45 ? " (默认)" : ""}
                </button>
              ))}
            </div>
          </div>

          <div className="form-field" style={{ marginTop: 16 }}>
            <label className="form-label">
              {IS_MAC
                ? "手动指定浏览器路径（支持直接填写 .app 路径，留空自动探测 Brave → Chrome）"
                : "手动指定浏览器可执行文件路径（留空则自动按 Brave → Chrome 探测）"}
            </label>
            <input
              type="text"
              className="form-input"
              placeholder={
                IS_MAC
                  ? "例如 /Applications/Brave Browser.app"
                  : "例如 C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe"
              }
              value={browserPath}
              onChange={(e) => setBrowserPath(e.target.value)}
            />
            <div className="muted-hint" style={{ marginTop: 6 }}>
              本工具不启用 Edge / Safari，推荐使用隐私防指纹更佳的{" "}
              <button
                type="button"
                className="btn-link"
                onClick={() =>
                  void api.openExternal("https://brave.com/download/")
                }
              >
                Brave 官方浏览器 (点击下载)
              </button>
            </div>
          </div>

          <div className="modal-footer">
            <button type="button" className="btn btn-ghost" onClick={onClose}>
              取消
            </button>
            <button
              type="button"
              className="btn btn-primary"
              disabled={saving}
              onClick={() => void handleSave()}
            >
              {saving ? "保存中..." : "保存设置"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// 5. 启动风险确认弹窗（非关键项黄灯确认 / 强制启动二次强确认）
// ============================================================================

export function RiskConfirmModal({
  mode,
  warnings,
  onCancel,
  onConfirm,
}: {
  mode: "non_critical_warn" | "force_bypass";
  warnings: CheckItemResult[];
  onCancel: () => void;
  onConfirm: () => void;
}) {
  return (
    <div className="modal-backdrop">
      <div className="modal-card">
        <div className="modal-header">
          <h3>
            {mode === "non_critical_warn"
              ? "检测到非阻断项风险提示"
              : "忽略安全检测 · 强制启动确认"}
          </h3>
          <button type="button" className="btn-icon-close" onClick={onCancel}>
            ×
          </button>
        </div>

        <div className="modal-body">
          {mode === "non_critical_warn" ? (
            <>
              <p className="confirm-desc">
                关键连通项（代理连接、出口国家、Claude 可访问）均已通过，但以下非关键项存在风险警告：
              </p>
              <div className="warning-list">
                {warnings.map((w) => (
                  <div key={w.id} className="warning-item">
                    <strong>
                      0{w.index} {w.title}：{w.summary}
                    </strong>
                    {w.error && <p>{w.error.userMessage}</p>}
                  </div>
                ))}
              </div>
            </>
          ) : (
            <p className="confirm-warning-text">
              您即将跳过五项启动前预检直接拉起浏览器！若当前代理不可用或出口地区受限，可能导致访问失败或风控风险（本次强制启动操作将记录至{" "}
              <code>launch.log</code>）。是否确认继续？
            </p>
          )}

          <div className="modal-footer">
            <button type="button" className="btn btn-ghost" onClick={onCancel}>
              取消启动
            </button>
            <button
              type="button"
              className={
                mode === "force_bypass"
                  ? "btn btn-danger-solid"
                  : "btn btn-warning-solid"
              }
              onClick={onConfirm}
            >
              {mode === "non_critical_warn"
                ? "知晓风险，继续启动"
                : "确认强制启动"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// 6. 窗口关闭保护弹窗 & 安全熔断即时告警弹窗（需求文档 5.2 & 8.3）
// ============================================================================

export function WindowCloseProtectionModal({
  onCancel,
  onMinimizeToTray,
  onConfirmExit,
}: {
  onCancel: () => void;
  onMinimizeToTray: () => void;
  onConfirmExit: () => void;
}) {
  return (
    <div className="modal-backdrop">
      <div className="modal-card">
        <div className="modal-header">
          <h3>安全浏览器正在受保护运行中</h3>
          <button type="button" className="btn-icon-close" onClick={onCancel}>
            ×
          </button>
        </div>
        <div className="modal-body">
          <p className="confirm-desc">
            当前安全浏览器正在通过本地转发器运行。请选择关闭窗口的方式：
          </p>
          <div className="close-choice-box">
            <button
              type="button"
              className="choice-card recommended"
              onClick={onMinimizeToTray}
            >
              <div className="choice-title">
                {IS_MAC
                  ? "隐藏到顶部菜单栏后台运行（推荐）"
                  : "最小化到系统托盘（推荐）"}
              </div>
              <div className="choice-sub">
                隐藏主窗口，继续在后台维持本地代理转发与 IP/DNS 泄露自动熔断保护
              </div>
            </button>

            <button
              type="button"
              className="choice-card danger"
              onClick={onConfirmExit}
            >
              <div className="choice-title">彻底退出程序</div>
              <div className="choice-sub">
                退出将同步强制关闭安全浏览器进程树并立即停止本地代理转发
              </div>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

export function WatchdogAlertModal({
  alert,
  onDismiss,
  onRecheckNow,
}: {
  alert: WatchdogAlertPayload;
  onDismiss: () => void;
  onRecheckNow: () => void;
}) {
  return (
    <div className="modal-backdrop">
      <div className="modal-card modal-alert-danger">
        <div className="modal-header">
          <h3>🚨 安全自动熔断已触发</h3>
          <button type="button" className="btn-icon-close" onClick={onDismiss}>
            ×
          </button>
        </div>
        <div className="modal-body">
          <div className="trip-headline">{alert.notificationBody}</div>
          <div className="muted-hint" style={{ marginBottom: 12 }}>
            触发时间：{alert.triggeredAt} · 本地转发器与安全浏览器进程树已原子切断
          </div>
          <ErrorBanner error={alert.bannerError} />
          <div className="modal-footer">
            <button type="button" className="btn btn-ghost" onClick={onDismiss}>
              稍后处理
            </button>
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => {
                onDismiss();
                onRecheckNow();
              }}
            >
              立即重新检测解锁
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// 7. 新建多账号独立浏览器环境弹窗
// ============================================================================

export function CreateBrowserEnvModal({
  suggestedName,
  onClose,
  onCreated,
}: {
  suggestedName: string;
  onClose: () => void;
  onCreated: (
    envs: { id: string; name: string }[],
    activeId: string,
    createdName: string,
  ) => void;
}) {
  const [envName, setEnvName] = useState(suggestedName);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<HumanizedError | null>(null);

  const handleSubmit = async () => {
    const trimmed = envName.trim();
    if (!trimmed) {
      setError({
        code: "EMPTY_ENV_NAME",
        userMessage: "请输入独立环境名称（例如：环境2）",
        technicalDetail: "",
      });
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const res = await api.createBrowserEnv(trimmed);
      onCreated(res.browserEnvs, res.activeBrowserEnvId, trimmed);
      onClose();
    } catch (err) {
      setError(normalizeError(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="modal-backdrop">
      <div className="modal-card" style={{ maxWidth: 420 }}>
        <div className="modal-header">
          <h3>新建独立浏览器环境</h3>
          <button type="button" className="btn-icon-close" onClick={onClose}>
            ×
          </button>
        </div>
        <div className="modal-body">
          {error && (
            <ErrorBanner error={error} onDismiss={() => setError(null)} />
          )}
          <div className="form-field">
            <label className="form-label">环境名称</label>
            <input
              type="text"
              className="form-input"
              placeholder="例如：环境2 / 工作账号"
              value={envName}
              maxLength={24}
              autoFocus
              onChange={(e) => setEnvName(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !saving) {
                  void handleSubmit();
                }
              }}
            />
            <span className="muted-hint" style={{ marginTop: 4 }}>
              每个环境自动映射独立的浏览器数据目录，多 Claude 账号 Cookie 与本地缓存完全物理隔离。
            </span>
          </div>
          <div className="modal-footer">
            <button type="button" className="btn btn-ghost" onClick={onClose}>
              取消
            </button>
            <button
              type="button"
              className="btn btn-primary"
              disabled={saving || !envName.trim()}
              onClick={() => void handleSubmit()}
            >
              {saving ? "创建中..." : "创建并切换"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
