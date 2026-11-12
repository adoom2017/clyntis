import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { save } from "@tauri-apps/plugin-dialog";
import { Download, Pause, Play, Search } from "lucide-react";
import { locale, t } from "../i18n";
import { type Log } from "../types";
import { type Perform } from "../components/common";

/** Quiet the parts of a log line the eye skips (network tags, local
 * addresses, arrows) so destinations and rules stand out. */
const quietLogPart =
  /(\[(?:TCP|UDP)\]|\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b|-->)/;
function LogPayload({ text }: { text: string }) {
  return (
    <span>
      {text.split(quietLogPart).map((part, i) =>
        i % 2 ? (
          <span key={i} className="log-quiet">
            {part}
          </span>
        ) : (
          part
        ),
      )}
    </span>
  );
}
export function LogPage({ logs, perform }: { logs: Log[]; perform: Perform }) {
  const [level, setLevel] = useState("all");
  const [paused, setPaused] = useState(false);
  const [frozen, setFrozen] = useState<Log[]>([]);
  const [query, setQuery] = useState("");
  // Newest first: logs arrive oldest-first, so reverse the filtered copy.
  const visible = (paused ? frozen : logs)
    .filter(
      (log) =>
        (level === "all" || log.type === level) &&
        log.payload.toLowerCase().includes(query.toLowerCase()),
    )
    .reverse();
  return (
    <>
      <div className="toolbar">
        <div>
          <select
            aria-label={t("日志级别")}
            value={level}
            onChange={(e) => setLevel(e.target.value)}
          >
            <option value="all">{t("全部")}</option>
            {["debug", "info", "warning", "error"].map((v) => (
              <option key={v}>{v}</option>
            ))}
          </select>
          <label className="search">
            <Search size={16} />
            <input
              aria-label={t("搜索日志")}
              placeholder={t("搜索日志")}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </label>
        </div>
        <div>
          <button
            className="button secondary"
            onClick={() => {
              if (!paused) setFrozen(logs);
              setPaused(!paused);
            }}
          >
            {paused ? <Play size={15} /> : <Pause size={15} />}
            {paused ? t("继续") : t("暂停")}
          </button>
          <button
            className="button secondary"
            onClick={() =>
              void perform(async () => {
                const path = await save({
                  defaultPath: "clyntis-logs.jsonl",
                  filters: [{ name: t("日志"), extensions: ["jsonl"] }],
                });
                if (path) await invoke("export_logs", { path });
              })
            }
          >
            <Download size={15} />
            {t("导出")}
          </button>
        </div>
      </div>
      <div className="panel logs-panel" role="log" aria-live="off">
        {visible.length ? (
          visible.map((log, i) => (
            <div className={`log-row ${log.type}`} key={`${log.time}-${i}`}>
              <time>
                {new Date(log.time * 1000).toLocaleTimeString(locale(), {
                  hour12: false,
                })}
              </time>
              <span className={`log-level ${log.type}`}>
                {log.type === "warning" ? "WARN" : log.type.toUpperCase()}
              </span>
              <LogPayload text={log.payload} />
            </div>
          ))
        ) : (
          <div className="table-empty">{t("暂无日志")}</div>
        )}
      </div>
      <p className="small muted table-note">
        {t("保留最近 2000 条，URL、UUID 和凭据已脱敏。")}
      </p>
    </>
  );
}
