import { useEffect, useState } from "react";
import { api, normalizeError } from "../api";
import type {
  HumanizedError,
  LicenseStatusView,
  ProxyView,
  SaveProxyInput,
} from "../types";
import { ErrorBanner } from "./ErrorBanner";

interface LicenseGateViewProps {
  license: LicenseStatusView;
  existingActiveProxy: ProxyView | null;
  onActivated: (hasProxyConfigured: boolean) => Promise<void>;
}

export function LicenseGateView({
  license,
  existingActiveProxy,
  onActivated,
}: LicenseGateViewProps) {
  const [name, setName] = useState(license.holderName ?? "");
  const [phone, setPhone] = useState(license.holderPhone ?? "");
  const [licenseCode, setLicenseCode] = useState("");

  const [quickSocksLink, setQuickSocksLink] = useState("");
  const [splitHint, setSplitHint] = useState<string | null>(null);

  const [host, setHost] = useState(existingActiveProxy?.host ?? "");
  const [portText, setPortText] = useState(
    existingActiveProxy ? String(existingActiveProxy.port) : "",
  );
  const [username, setUsername] = useState(existingActiveProxy?.username ?? "");
  const [password, setPassword] = useState("");

  const [submitting, setSubmitting] = useState(false);
  const [copiedMc, setCopiedMc] = useState(false);
  const [formError, setFormError] = useState<HumanizedError | null>(
    license.expiredMessage
      ? {
          code: "LICENSE_EXPIRED",
          userMessage: license.expiredMessage,
          technicalDetail: "",
        }
      : null,
  );

  useEffect(() => {
    if (existingActiveProxy && !host && !portText) {
      setHost(existingActiveProxy.host);
      setPortText(String(existingActiveProxy.port));
      setUsername(existingActiveProxy.username);
    }
  }, [existingActiveProxy, host, portText]);

  const tryAutoSplitProxy = async (rawText: string) => {
    const trimmed = rawText.trim();
    if (!trimmed || !trimmed.includes(":")) {
      setSplitHint(null);
      return;
    }
    try {
      const parsed = await api.parseProxyText(trimmed);
      setHost(parsed.host);
      setPortText(String(parsed.port));
      setUsername(parsed.username);
      setPassword(parsed.password);
      setSplitHint("✓ 已自动拆分填入下方四个代理字段");
      setFormError(null);
    } catch {
      // 用户尚在输入过程中时不打断，仅当点击提交或完整粘贴失败时提示
      setSplitHint(null);
    }
  };

  const handleCopyMachineCode = async () => {
    try {
      await navigator.clipboard.writeText(license.machineCode);
      setCopiedMc(true);
      setTimeout(() => setCopiedMc(false), 2000);
    } catch {
      // ignore clipboard error
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);

    if (!name.trim()) {
      setFormError({
        code: "NAME_EMPTY",
        userMessage: "请填写您的授权姓名",
        technicalDetail: "",
      });
      return;
    }
    if (!phone.trim()) {
      setFormError({
        code: "PHONE_EMPTY",
        userMessage: "请填写您的授权手机号",
        technicalDetail: "",
      });
      return;
    }
    if (!licenseCode.trim()) {
      setFormError({
        code: "CODE_EMPTY",
        userMessage: "请填写管理员发放的授权码（CL-XXXX-...）",
        technicalDetail: "",
      });
      return;
    }

    let proxyInput: SaveProxyInput | null = null;
    const trimmedHost = host.trim();
    const trimmedPort = portText.trim();

    if (trimmedHost || trimmedPort) {
      const portNum = Number(trimmedPort);
      if (!trimmedHost) {
        setFormError({
          code: "PROXY_HOST_EMPTY",
          userMessage: "请填写代理主机地址（若暂不配置代理，请清空主机与端口框）",
          technicalDetail: "",
        });
        return;
      }
      if (!/^\d+$/.test(trimmedPort) || portNum < 1 || portNum > 65535) {
        setFormError({
          code: "PROXY_PORT_INVALID",
          userMessage: "代理端口必须为 1–65535 之间的整数",
          technicalDetail: "",
        });
        return;
      }

      const trimmedUser = username.trim();
      const reusingExisting =
        existingActiveProxy &&
        existingActiveProxy.host === trimmedHost &&
        existingActiveProxy.port === portNum &&
        existingActiveProxy.username === trimmedUser;

      const authEnabled = Boolean(
        trimmedUser || password || (reusingExisting && existingActiveProxy.authEnabled),
      );

      if (authEnabled && !trimmedUser) {
        setFormError({
          code: "PROXY_USER_EMPTY",
          userMessage: "填写了代理密码时，代理用户名不能为空",
          technicalDetail: "",
        });
        return;
      }

      if (
        authEnabled &&
        !password &&
        !(reusingExisting && existingActiveProxy?.hasPassword)
      ) {
        setFormError({
          code: "PROXY_PASS_EMPTY",
          userMessage: "请填写 SOCKS5 代理密码",
          technicalDetail: "",
        });
        return;
      }

      proxyInput = {
        id: reusingExisting ? existingActiveProxy.id : null,
        name: reusingExisting
          ? existingActiveProxy.name
          : `SOCKS5 (${trimmedHost})`,
        host: trimmedHost,
        port: portNum,
        authEnabled,
        username: trimmedUser,
        password: password ? password : null,
      };
    }

    setSubmitting(true);
    try {
      await api.activateLicense({
        name: name.trim(),
        phone: phone.trim(),
        licenseCode: licenseCode.trim(),
        proxyInput,
      });
      await onActivated(proxyInput !== null || existingActiveProxy !== null);
    } catch (err) {
      setFormError(normalizeError(err));
    } finally {
      setSubmitting(false);
    }
  };

  const canReuseSavedPassword = Boolean(
    existingActiveProxy &&
      existingActiveProxy.hasPassword &&
      existingActiveProxy.host === host.trim() &&
      String(existingActiveProxy.port) === portText.trim() &&
      existingActiveProxy.username === username.trim(),
  );

  return (
    <div className="auth-gate-screen">
      <form className="auth-gate-card" onSubmit={(e) => void handleSubmit(e)}>
        <div className="auth-gate-top-row">
          <span className="auth-env-kicker">CLAUDE ENVIRONMENT</span>
          <button
            type="button"
            className="machine-code-chip"
            onClick={() => void handleCopyMachineCode()}
            title="本机唯一设备识别码（首次使用授权码登录时将自动绑定本机，转发他人无效）"
          >
            <span>设备码: {license.machineCode}</span>
            <strong>{copiedMc ? "已复制" : "复制"}</strong>
          </button>
        </div>

        <h1 className="auth-gate-title">授权访问</h1>
        <p className="auth-gate-subtitle">
          完成身份验证后进入 Claude安全客户端。
        </p>

        {formError && (
          <div className="auth-error-wrap">
            <ErrorBanner
              error={formError}
              onDismiss={() => setFormError(null)}
            />
          </div>
        )}

        <div className="auth-grid-2">
          <div className="auth-field">
            <label>姓名</label>
            <input
              type="text"
              className="auth-input"
              placeholder="请输入授权姓名"
              value={name}
              onChange={(e) => setName(e.target.value)}
              autoFocus
            />
          </div>
          <div className="auth-field">
            <label>手机号</label>
            <input
              type="text"
              className="auth-input"
              placeholder="请输入授权手机号"
              value={phone}
              onChange={(e) => setPhone(e.target.value)}
            />
          </div>
        </div>

        <div className="auth-field">
          <label>授权码</label>
          <input
            type="text"
            className="auth-input auth-code-input"
            placeholder="CL-XXXX-XXXX-XXXX-XXXX"
            value={licenseCode}
            onChange={(e) => setLicenseCode(e.target.value)}
          />
        </div>

        <div className="auth-field">
          <label>快速填写完整 SOCKS5 链接</label>
          <input
            type="text"
            className="auth-input"
            placeholder="socks5://用户名:密码@主机:端口"
            value={quickSocksLink}
            onChange={(e) => {
              const val = e.target.value;
              setQuickSocksLink(val);
              void tryAutoSplitProxy(val);
            }}
          />
          <span className={`auth-sub-note ${splitHint ? "ok" : ""}`}>
            {splitHint ?? "粘贴后自动拆分到下方四个字段（兼容 host:port:user:pass）"}
          </span>
        </div>

        <div className="auth-grid-2">
          <div className="auth-field">
            <label>代理主机</label>
            <input
              type="text"
              className="auth-input"
              placeholder="例如 accel.ipflygates.com"
              value={host}
              onChange={(e) => setHost(e.target.value)}
            />
          </div>
          <div className="auth-field">
            <label>端口</label>
            <input
              type="text"
              className="auth-input"
              placeholder="例如 5001"
              value={portText}
              onChange={(e) => setPortText(e.target.value)}
            />
          </div>
        </div>

        <div className="auth-grid-2">
          <div className="auth-field">
            <label>用户名</label>
            <input
              type="text"
              className="auth-input"
              placeholder="代理用户名（无认证可留空）"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
          </div>
          <div className="auth-field">
            <label>密码</label>
            <input
              type="password"
              className="auth-input"
              placeholder={
                canReuseSavedPassword
                  ? "••••••••（已加密保存，留空沿用）"
                  : "代理密码（无认证可留空）"
              }
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
        </div>

        <button
          type="submit"
          className="auth-submit-btn"
          disabled={submitting}
        >
          {submitting ? "正在校验授权与配置..." : "校验并进入客户端"}
        </button>
      </form>
    </div>
  );
}
