import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Network, Search, X } from "lucide-react";
import { t } from "../i18n";
import { bytes, type Connection, type Connections } from "../types";
import { usePageVisible } from "../visibility";
import { Empty, type Perform } from "../components/common";

export function ConnectionPage({
  running,
  perform,
}: {
  running: boolean;
  perform: Perform;
}) {
  const [items, setItems] = useState<Connection[]>([]);
  const [query, setQuery] = useState("");
  const [failed, setFailed] = useState(false);
  const refresh = useCallback(async () => {
    const value = await invoke<Connections>("connections");
    setItems(value.connections);
    setFailed(false);
  }, []);
  const shown = usePageVisible();
  useEffect(() => {
    if (!running || !shown) return;
    let alive = true;
    const tick = () =>
      void refresh().catch(() => {
        if (alive) setFailed(true);
      });
    tick();
    const timer = setInterval(tick, 2000);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, [running, shown, refresh]);
  if (!running)
    return (
      <Empty
        icon={<Network />}
        title={t("未连接")}
        text={t("连接后显示活跃连接。")}
      />
    );
  const visible = items.filter((item) =>
    `${item.metadata.host} ${item.chains.join(" ")}`
      .toLowerCase()
      .includes(query.toLowerCase()),
  );
  return (
    <>
      <div className="toolbar">
        <label className="search">
          <Search size={16} />
          <input
            placeholder={t("搜索目标或代理链")}
            aria-label={t("搜索连接")}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </label>
        <button
          className="button secondary"
          disabled={!items.length}
          onClick={() =>
            void perform(async () => {
              await invoke("close_connection", { id: null });
              await refresh();
            })
          }
        >
          {t("全部断开")}
        </button>
      </div>
      {failed && (
        <p className="inline-error" role="alert">
          {t("刷新失败，正在重试。")}
        </p>
      )}
      <div className="panel table-wrap">
        <table className="connection-table">
          <thead>
            <tr>
              <th>{t("目标地址")}</th>
              <th>{t("协议 / 代理链")}</th>
              <th className="num">{t("下载")}</th>
              <th className="num">{t("上传")}</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {visible.map((item) => (
              <tr key={item.id}>
                <td>
                  <strong>{item.metadata.host}</strong>
                  <span className="muted">:{item.metadata.port}</span>
                </td>
                <td>
                  <span className="route-line">
                    <span className="tiny-tag">
                      {item.network.toUpperCase()}
                    </span>
                    <span className="muted">{item.chains.join(" → ")}</span>
                  </span>
                </td>
                <td className="num">{bytes(item.download)}</td>
                <td className="num">{bytes(item.upload)}</td>
                <td>
                  <button
                    className="icon-button"
                    aria-label={t("关闭 {host} 连接", {
                      host: item.metadata.host,
                    })}
                    onClick={() =>
                      void perform(async () => {
                        await invoke("close_connection", { id: item.id });
                        await refresh();
                      })
                    }
                  >
                    <X size={15} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!visible.length && (
          <div className="table-empty">
            {items.length ? t("无匹配结果") : t("暂无连接")}
          </div>
        )}
      </div>
      <p className="small muted table-note">
        {t("{count} 个连接", { count: items.length })}
      </p>
    </>
  );
}
