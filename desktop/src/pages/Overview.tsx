import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  Activity,
  ArrowDown,
  ArrowUp,
  ChevronRight,
  LoaderCircle,
  Network,
  Power,
  Wifi,
} from "lucide-react";
import { type Perform, Stat } from "../components/common";
import { AdblockPanel } from "../features/Adblock";
import { RewritePanel } from "../features/Rewrite";
import { TrafficDetailsModal } from "../features/TrafficDetails";
import { t } from "../i18n";
import {
  bytes,
  captureText,
  modeText,
  statusText,
  type Capture,
  type Connections,
  type Mode,
  type ProfileSummary,
  type NetworkStatus,
  type Snapshot,
  type Traffic,
} from "../types";
import { usePageVisible } from "../visibility";

export function ConnectionStats({
  running,
  paused = false,
  onOpenConnections,
  onOpenTraffic,
}: {
  running: boolean;
  paused?: boolean;
  onOpenConnections?: () => void;
  onOpenTraffic?: () => void;
}) {
  const [value, setValue] = useState({
    count: 0,
    uploadTotal: 0,
    downloadTotal: 0,
  });
  const visible = usePageVisible();
  useEffect(() => {
    let live = true;
    if (!running) {
      setValue({ count: 0, uploadTotal: 0, downloadTotal: 0 });
      return;
    }
    if (!visible || paused) return;
    let timer: number | undefined;
    const loop = async () => {
      try {
        const v = await invoke<Connections>("connections");
        if (live) {
          const count = v.connections.length;
          setValue((prev) =>
            prev.count === count &&
            prev.uploadTotal === v.uploadTotal &&
            prev.downloadTotal === v.downloadTotal
              ? prev
              : {
                  count,
                  uploadTotal: v.uploadTotal,
                  downloadTotal: v.downloadTotal,
                },
          );
        }
      } catch {
        /* ignore transient errors */
      }
      if (live) {
        timer = window.setTimeout(() => void loop(), 2000);
      }
    };
    void loop();
    return () => {
      live = false;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [running, visible, paused]);
  return (
    <>
      <Stat
        label={t("连接数")}
        value={String(value.count)}
        icon={<Network size={14} />}
        onClick={running ? onOpenConnections : undefined}
        title={running ? t("查看活跃连接") : undefined}
      />
      <Stat
        label={t("总流量")}
        value={bytes(value.uploadTotal + value.downloadTotal)}
        icon={<Activity size={14} />}
        onClick={running ? onOpenTraffic : undefined}
        title={running ? t("查看流量详情") : undefined}
      />
    </>
  );
}
export function TrafficChart({ values }: { values: Traffic[] }) {
  const max = Math.max(1024, ...values.flatMap((v) => [v.up, v.down]));
  const line = (key: keyof Traffic) =>
    Array.from({ length: 60 }, (_, i) => {
      const value = values[i - (60 - values.length)]?.[key] ?? 0;
      return `${(i * 600) / 59},${132 - (value / max) * 110}`;
    }).join(" ");
  return (
    <div className="traffic-chart">
      <span className="chart-max">{bytes(max)}/s</span>
      <span className="chart-max half">{bytes(max / 2)}/s</span>
      <svg
        viewBox="0 0 600 150"
        preserveAspectRatio="none"
        role="img"
        aria-label={t("最近 60 秒上传和下载速率")}
      >
        <defs>
          <linearGradient id="download-fill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--accent)" stopOpacity=".16" />
            <stop offset="100%" stopColor="var(--accent)" stopOpacity="0" />
          </linearGradient>
          <linearGradient id="upload-fill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--upload)" stopOpacity=".22" />
            <stop offset="100%" stopColor="var(--upload)" stopOpacity="0" />
          </linearGradient>
        </defs>
        {[22, 77, 132].map((y) => (
          <line
            key={y}
            x1="0"
            x2="600"
            y1={y}
            y2={y}
            stroke="var(--border)"
            vectorEffect="non-scaling-stroke"
          />
        ))}
        <polygon
          points={`0,150 ${line("down")} 600,150`}
          fill="url(#download-fill)"
        />
        <polyline
          points={line("down")}
          fill="none"
          stroke="var(--accent)"
          strokeWidth="1.5"
          strokeLinejoin="round"
          vectorEffect="non-scaling-stroke"
        />
        <polygon
          points={`0,132 ${line("up")} 600,132`}
          fill="url(#upload-fill)"
        />
        <polyline
          points={line("up")}
          fill="none"
          stroke="var(--upload)"
          strokeWidth="2"
          strokeLinejoin="round"
          vectorEffect="non-scaling-stroke"
        />
      </svg>
    </div>
  );
}
/** The profile's networks the device is on, while the profile defines any. */
export function NetworkPanel({
  profileId = null,
}: {
  profileId?: string | null;
} = {}) {
  const [status, setStatus] = useState<NetworkStatus | null>(null);
  const visible = usePageVisible();
  const lastProfile = useRef(profileId);
  const stopForCurrent = useRef(false);
  useEffect(() => {
    if (lastProfile.current !== profileId) {
      lastProfile.current = profileId;
      stopForCurrent.current = false;
      setStatus(null);
    }
    if (!visible || stopForCurrent.current) return;
    let alive = true;
    let timer: number | undefined;
    const load = async () => {
      try {
        const next = await invoke<NetworkStatus>("network_status");
        if (!alive) return;
        setStatus(next);
        if (next?.defined === false) {
          stopForCurrent.current = true;
          return;
        }
      } catch {
        if (!alive) return;
        setStatus(null);
      }
      if (alive) {
        timer = window.setTimeout(() => void load(), 5000);
      }
    };
    void load();
    return () => {
      alive = false;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [visible, profileId]);
  if (!status?.defined) return null;
  const facts = [
    status.info.type &&
      { wifi: "Wi-Fi", wired: t("有线"), cellular: t("蜂窝") }[
        status.info.type
      ],
    status.info.addresses.find((address) => !address.includes(":")),
    status.info.gateways.length > 0 &&
      t("网关 {gateways}", { gateways: status.info.gateways[0] }),
  ].filter(Boolean);
  return (
    <section className="panel network-panel">
      <div className="panel-title">
        <h3>
          <Wifi size={15} /> {t("当前网络")}
        </h3>
        <strong>
          {status.networks.length ? status.networks.join(t("、")) : t("未匹配")}
        </strong>
      </div>
      <p className="muted small">
        {facts.join(" · ")}
        {status.override &&
          ` · ${t("生效的覆盖：{override}", { override: status.override })}`}
      </p>
    </section>
  );
}

/** The overview page: connection, traffic and routing mode. */
export function OverviewPage({
  state,
  traffic,
  selected,
  running,
  transitioning,
  disabled,
  perform,
  onAddProfile,
  onOpenConnections,
}: {
  state: Snapshot;
  traffic: Traffic[];
  selected: ProfileSummary | undefined;
  running: boolean;
  transitioning: boolean;
  disabled: boolean;
  perform: Perform;
  onAddProfile: () => void;
  onOpenConnections?: () => void;
}) {
  const [trafficOpen, setTrafficOpen] = useState(false);
  useEffect(() => {
    if (!running) setTrafficOpen(false);
  }, [running]);
  return (
    <>
      <section className={`panel connect-card ${running ? "is-running" : ""}`}>
        <div className="connection-copy">
          <h2>{statusText[state.status]}</h2>
          {selected ? (
            <p>{selected.name}</p>
          ) : (
            <button className="text-button" onClick={onAddProfile}>
              {t("添加配置")}
              <ChevronRight size={14} />
            </button>
          )}
          <div className="connection-details">
            <div className="segmented" role="group" aria-label={t("接管方式")}>
              {(["manual", "system", "tun"] as Capture[]).map((capture) => (
                <button
                  key={capture}
                  disabled={disabled}
                  aria-pressed={state.settings.capture === capture}
                  className={
                    state.settings.capture === capture ? "selected" : ""
                  }
                  onClick={() =>
                    void perform(() => invoke("set_capture", { capture }))
                  }
                >
                  {captureText[capture]}
                </button>
              ))}
            </div>
            <span>{modeText[state.mode]}</span>
            <span>127.0.0.1:{state.settings.mixedPort}</span>
          </div>
        </div>
        <button
          className={`power-button ${running ? "on" : ""}`}
          disabled={disabled || !selected}
          aria-label={running ? t("停止连接") : t("启动连接")}
          title={running ? t("断开") : t("连接")}
          onClick={() => void perform(() => invoke(running ? "stop" : "start"))}
        >
          {transitioning ? (
            <LoaderCircle size={26} className="spin" />
          ) : (
            <Power size={26} />
          )}
        </button>
      </section>
      <div className="stat-grid">
        <Stat
          label={t("下载")}
          value={`${bytes(traffic.at(-1)?.down ?? 0)}/s`}
          icon={<ArrowDown size={14} />}
          tone="green"
        />
        <Stat
          label={t("上传")}
          value={`${bytes(traffic.at(-1)?.up ?? 0)}/s`}
          icon={<ArrowUp size={14} />}
          tone="blue"
        />
        <ConnectionStats
          running={running}
          paused={trafficOpen}
          onOpenConnections={onOpenConnections}
          onOpenTraffic={() => setTrafficOpen(true)}
        />
      </div>
      <div className="overview-grid">
        <section className="panel traffic-panel">
          <div className="panel-title">
            <h3>{t("流量")}</h3>
            <div className="traffic-title-actions">
              <div className="chart-legend">
                <span>
                  <i className="legend-dot green" />
                  {t("下载")}
                  <b>{bytes(traffic.at(-1)?.down ?? 0)}/s</b>
                </span>
                <span>
                  <i className="legend-dot blue" />
                  {t("上传")}
                  <b>{bytes(traffic.at(-1)?.up ?? 0)}/s</b>
                </span>
              </div>
              {running && (
                <button
                  type="button"
                  className="text-button"
                  onClick={() => setTrafficOpen(true)}
                >
                  {t("详情")}
                </button>
              )}
            </div>
          </div>
          <TrafficChart values={traffic} />
          <div className="chart-axis">
            <span>60s</span>
            <span>30s</span>
            <span>{t("现在")}</span>
          </div>
        </section>
        <section className="panel routing-panel">
          <div className="panel-title">
            <h3>{t("路由模式")}</h3>
          </div>
          {(["rule", "global", "direct"] as Mode[]).map((mode) => (
            <button
              key={mode}
              className={`mode-option ${state.mode === mode ? "selected" : ""}`}
              disabled={disabled || !selected}
              onClick={() => void perform(() => invoke("set_mode", { mode }))}
            >
              <span className="radio-mark">
                {state.mode === mode && <span />}
              </span>
              <span>
                <strong>{modeText[mode]}</strong>
                <small>
                  {
                    {
                      rule: t("按规则分流"),
                      global: t("全部走代理"),
                      direct: t("全部直连"),
                    }[mode]
                  }
                </small>
              </span>
            </button>
          ))}
        </section>
      </div>
      {running && <NetworkPanel profileId={state.selected} />}
      {running && <AdblockPanel settings={state.settings} perform={perform} />}
      {running && <RewritePanel compact perform={perform} />}
      {running && trafficOpen && (
        <TrafficDetailsModal
          running={running}
          perform={perform}
          onClose={() => setTrafficOpen(false)}
        />
      )}
    </>
  );
}
