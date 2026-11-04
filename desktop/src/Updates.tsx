import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { Download, RefreshCw } from "lucide-react";
import { t } from "./i18n";
import { bytes } from "./types";

export interface UpdateState {
  phase:
    | "disabled"
    | "idle"
    | "checking"
    | "available"
    | "current"
    | "downloading"
    | "ready"
    | "installing"
    | "error";
  version: string | null;
  notes: string | null;
  error: string | null;
  downloaded: number;
  total: number | null;
  checkedAt: number | null;
}

export function useUpdates() {
  const [state, setState] = useState<UpdateState | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const active = useRef(false);
  useEffect(() => {
    let alive = true;
    let received = false;
    let off: (() => void) | undefined;
    void (async () => {
      try {
        const unlisten = await listen<UpdateState>(
          "app-update",
          ({ payload }) => {
            received = true;
            if (alive) {
              setState(payload);
              if (!payload.error) setError(null);
            }
          },
        );
        if (!alive) {
          unlisten();
          return;
        }
        off = unlisten;
        const current = await invoke<UpdateState>("app_update_state");
        if (alive && !received && current?.phase) setState(current);
      } catch (e) {
        if (alive) setError(String(e));
      }
    })();
    return () => {
      alive = false;
      off?.();
    };
  }, []);
  const run = async (
    command: "check_app_update" | "download_app_update" | "install_app_update",
  ) => {
    if (active.current) return;
    active.current = true;
    setPending(true);
    setError(null);
    try {
      await invoke(command);
    } catch (e) {
      setError(String(e));
    } finally {
      active.current = false;
      setPending(false);
    }
  };
  return { state, pending, error, run };
}
export type UpdateController = ReturnType<typeof useUpdates>;

export function UpdatesPanel({
  updates,
  busy,
  onInstall,
}: {
  updates: UpdateController;
  busy: boolean;
  onInstall: () => void;
}) {
  const { state, pending, error, run } = updates;
  const phase = state?.phase;
  const working =
    pending || ["checking", "downloading", "installing"].includes(phase ?? "");
  let message = t("检查是否有新版本");
  if (phase === "disabled")
    message = t("此构建未配置更新签名，请安装官方发布版本以启用自动更新。");
  if (phase === "checking") message = t("正在检查客户端更新…");
  if (phase === "current") message = t("当前已是最新版本");
  if (phase === "available")
    message = t("发现新版本 {version}", { version: state!.version ?? "" });
  if (phase === "downloading") message = t("正在下载并校验更新…");
  if (phase === "ready") message = t("更新包已验证，可以安装");
  if (phase === "installing") message = t("正在恢复网络设置并安装更新…");
  if (phase === "error") message = t("更新未完成，请检查网络后重试");
  const failure = error || state?.error;
  return (
    <section
      className="panel settings-section app-updates"
      aria-label={t("客户端更新")}
    >
      <div className="setting-row">
        <div>
          <strong>
            {t("当前版本 {version}", { version: __APP_VERSION__ })}
          </strong>
          <p role="status">{message}</p>
          {state?.checkedAt && (
            <p>
              {t("上次检查：{time}", {
                time: new Date(state.checkedAt * 1000).toLocaleString(),
              })}
            </p>
          )}
        </div>
        <div className="service-actions">
          <button
            className="button secondary"
            disabled={
              !state ||
              phase === "disabled" ||
              phase === "ready" ||
              working ||
              busy
            }
            onClick={() => void run("check_app_update")}
          >
            <RefreshCw size={14} />
            {t("检查客户端更新")}
          </button>
          {state?.version && phase !== "ready" && phase !== "installing" && (
            <button
              className="button primary"
              disabled={working || busy}
              onClick={() => void run("download_app_update")}
            >
              <Download size={14} />
              {t("下载更新")}
            </button>
          )}
          {phase === "ready" && (
            <button
              className="button primary"
              disabled={working || busy}
              onClick={onInstall}
            >
              {t("安装并重启")}
            </button>
          )}
        </div>
      </div>
      {phase === "downloading" && (
        <div className="update-progress">
          <progress
            aria-label={t("更新下载进度")}
            max={state?.total || undefined}
            value={state?.total ? state.downloaded : undefined}
          />
          <span>
            {bytes(state?.downloaded ?? 0)}
            {state?.total ? ` / ${bytes(state.total)}` : ""}
          </span>
        </div>
      )}
      {failure && (
        <p className="service-note" role="alert">
          {failure}
        </p>
      )}
      {state?.notes && (
        <details className="update-notes">
          <summary>{t("版本说明")}</summary>
          <p>{state.notes}</p>
        </details>
      )}
    </section>
  );
}
