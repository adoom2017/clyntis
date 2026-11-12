import { useEffect, useState } from "react";
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

export function ConnectionStats({ running }: { running: boolean }) {
  const [value, setValue] = useState<Connections>({
    connections: [],
    uploadTotal: 0,
    downloadTotal: 0,
  });
  const visible = usePageVisible();
  useEffect(() => {
    let live = true;
    if (!running) {
      setValue({ connections: [], uploadTotal: 0, downloadTotal: 0 });
      return;
    }
    if (!visible) return;
    const update = () =>
      void invoke<Connections>("connections")
        .then((v) => {
          if (live) setValue(v);
        })
        .catch(() => {});
    update();
    const timer = setInterval(update, 2000);
    return () => {
      live = false;
      clearInterval(timer);
    };
  }, [running, visible]);
  return (
    <>
      <Stat
        label={t("连接数")}
        value={String(value.connections.length)}
        icon={<Network size={14} />}
      />
      <Stat
        label={t("总流量")}
        value={bytes(value.uploadTotal + value.downloadTotal)}
        icon={<Activity size={14} />}
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
export function NetworkPanel() {
  const [status, setStatus] = useState<NetworkStatus | null>(null);
  const visible = usePageVisible();
  useEffect(() => {
    if (!visible) return;
    const load = () =>
      void invoke<NetworkStatus>("network_status")
        .then(setStatus)
        .catch(() => setStatus(null));
    load();
    const timer = window.setInterval(load, 5000);
    return () => window.clearInterval(timer);
  }, [visible]);
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
}: {
  state: Snapshot;
  traffic: Traffic[];
  selected: ProfileSummary | undefined;
  running: boolean;
  transitioning: boolean;
  disabled: boolean;
  perform: Perform;
  onAddProfile: () => void;
}) {
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
        <ConnectionStats running={running} />
      </div>
      <div className="overview-grid">
        <section className="panel traffic-panel">
          <div className="panel-title">
            <h3>{t("流量")}</h3>
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
      {running && <NetworkPanel />}
      {running && <AdblockPanel settings={state.settings} perform={perform} />}
    </>
  );
}
