import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { save } from "@tauri-apps/plugin-dialog";
import {
  Ban,
  Copy,
  Download,
  KeyRound,
  Pause,
  Play,
  RefreshCw,
  ScanSearch,
  Search,
  ShieldCheck,
  Trash2,
} from "lucide-react";
import { locale, t } from "./i18n";
import { usePageVisible } from "./visibility";
import { Empty, Modal, Setting, Toggle, type Perform } from "./App";
import {
  bytes,
  type BodyView,
  type CustomRules,
  type MitmInfo,
  type RequestDetail,
  type RequestEntry,
  type RewriteStatus,
  type Settings,
} from "./types";

/** Rows the page keeps; the core keeps its own, larger log. */
const ROWS = 5000;
const POLL_MS = 1500;

type Row = RequestEntry & { key: string };
type Filter = "all" | "http" | "rewritten" | "rejected" | "connections";

const time = (ms: number) =>
  new Date(ms).toLocaleTimeString(locale(), { hour12: false });
const duration = (ms: number) =>
  ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(ms < 10000 ? 1 : 0)} s`;

function matches(row: Row, filter: Filter, query: string) {
  if (filter === "http" && row.status !== "http") return false;
  if (filter === "rewritten" && !row.http?.rewrite) return false;
  if (filter === "rejected" && row.status !== "rejected") return false;
  if (filter === "connections" && row.status !== "closed") return false;
  if (!query) return true;
  const text =
    `${row.host} ${row.http?.url ?? ""} ${row.rule} ${row.chain} ${row.http?.contentType ?? ""} ${row.http?.rewrite ?? ""}`.toLowerCase();
  return query
    .toLowerCase()
    .split(/\s+/)
    .every((word) => text.includes(word));
}

export function RequestsPage({
  running,
  settings,
  perform,
  confirm,
}: {
  running: boolean;
  settings: Settings;
  perform: Perform;
  confirm: (modal: React.ReactNode) => void;
}) {
  const [rows, setRows] = useState<Row[]>([]);
  const [paused, setPaused] = useState(false);
  const [filter, setFilter] = useState<Filter>("all");
  const [query, setQuery] = useState("");
  const [failed, setFailed] = useState(false);
  const [selected, setSelected] = useState<Row | null>(null);
  const cursor = useRef(0);
  const generation = useRef(0);
  const shown = usePageVisible();

  const fetchNew = useCallback(async () => {
    // A full log arrives in pages of 1000.
    for (let page = 0; page < 8; page++) {
      const result = await invoke<{ requests: RequestEntry[]; next: number }>(
        "requests",
        { after: cursor.current },
      );
      if (result.next < cursor.current) {
        // The core restarted: its ids start over. Keep what is shown.
        generation.current += 1;
        cursor.current = 0;
        continue;
      }
      cursor.current = result.next;
      if (result.requests.length) {
        const prefix = `${generation.current}:`;
        const added = result.requests.map((r) => ({
          ...r,
          key: prefix + r.id,
        }));
        setRows((current) => {
          const next = current.concat(added);
          return next.length > ROWS ? next.slice(next.length - ROWS) : next;
        });
      }
      if (result.requests.length < 1000) break;
    }
  }, []);

  useEffect(() => {
    if (!running || !shown || paused) return;
    let alive = true;
    const tick = () =>
      void fetchNew()
        .then(() => alive && setFailed(false))
        .catch(() => alive && setFailed(true));
    tick();
    const timer = window.setInterval(tick, POLL_MS);
    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, [running, shown, paused, fetchNew]);

  const visible = useMemo(() => {
    const q = query.trim();
    const list = rows.filter((row) => matches(row, filter, q));
    return list.reverse();
  }, [rows, filter, query]);
  const counts = useMemo(
    () => ({
      all: rows.length,
      http: rows.filter((r) => r.status === "http").length,
      rewritten: rows.filter((r) => r.http?.rewrite).length,
      rejected: rows.filter((r) => r.status === "rejected").length,
      connections: rows.filter((r) => r.status === "closed").length,
    }),
    [rows],
  );

  const block = (host: string) =>
    confirm(
      <BlockConfirm
        host={host}
        perform={perform}
        onClose={() => confirm(null)}
      />,
    );

  return (
    <>
      <MitmPanel running={running} settings={settings} perform={perform} />
      {running && settings.overrides.rewrite?.enabled && (
        <RewritePanel decrypting={!!settings.overrides.mitm?.enable} />
      )}
      {!running ? (
        <Empty
          icon={<ScanSearch />}
          title={t("未连接")}
          text={t("连接后记录经过代理的请求。")}
        />
      ) : (
        <>
          <div className="toolbar">
            <div>
              <div className="segmented" role="group" aria-label={t("筛选")}>
                {(
                  [
                    ["all", t("全部")],
                    ["http", "HTTP"],
                    ...(settings.overrides.rewrite?.enabled || counts.rewritten
                      ? ([["rewritten", t("已重写")]] as [Filter, string][])
                      : []),
                    ["rejected", t("已拦截")],
                    ["connections", t("连接")],
                  ] as [Filter, string][]
                ).map(([id, label]) => (
                  <button
                    key={id}
                    aria-pressed={filter === id}
                    className={filter === id ? "selected" : ""}
                    onClick={() => setFilter(id)}
                  >
                    {label}
                    <span className="segment-count">{counts[id]}</span>
                  </button>
                ))}
              </div>
              <label className="search">
                <Search size={16} />
                <input
                  placeholder={t("搜索域名、URL 或规则")}
                  aria-label={t("搜索请求")}
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                />
              </label>
            </div>
            <div className="requests-actions">
              <button
                className="button secondary"
                onClick={() => setPaused((p) => !p)}
              >
                {paused ? <Play size={15} /> : <Pause size={15} />}
                {paused ? t("继续") : t("暂停")}
              </button>
              <button
                className="button secondary"
                disabled={!rows.length}
                title={t(
                  "HAR 含请求和返回内容，可用 Charles、Proxyman 或浏览器开发者工具打开；CSV 含全部记录，可用 Excel 打开",
                )}
                onClick={() =>
                  void perform(async () => {
                    const stamp = new Date()
                      .toISOString()
                      .slice(0, 19)
                      .replace(/[-:T]/g, "");
                    const path = await save({
                      defaultPath: `clyntis-requests-${stamp}.har`,
                      filters: [
                        {
                          name: t("HAR（HTTP 请求和内容）"),
                          extensions: ["har"],
                        },
                        { name: t("CSV（全部记录）"), extensions: ["csv"] },
                      ],
                    });
                    if (path) await invoke("export_requests", { path });
                  }, t("已导出"))
                }
              >
                <Download size={15} />
                {t("导出")}
              </button>
              <button
                className="button secondary"
                disabled={!rows.length}
                onClick={() =>
                  void perform(async () => {
                    await invoke("clear_requests");
                    setRows([]);
                  })
                }
              >
                <Trash2 size={15} />
                {t("清空")}
              </button>
            </div>
          </div>
          {failed && (
            <p className="inline-error" role="alert">
              {t("刷新失败，正在重试。")}
            </p>
          )}
          <div className="panel table-wrap">
            <table className="connection-table requests-table">
              <thead>
                <tr>
                  <th>{t("时间")}</th>
                  <th>{t("请求")}</th>
                  <th>{t("状态")}</th>
                  <th>{t("规则 / 代理")}</th>
                  <th className="num">{t("大小")}</th>
                  <th className="num">{t("耗时")}</th>
                </tr>
              </thead>
              <tbody>
                {visible.slice(0, 1000).map((row) => (
                  <RequestRow
                    key={row.key}
                    row={row}
                    onOpen={() => setSelected(row)}
                  />
                ))}
              </tbody>
            </table>
            {!visible.length && (
              <div className="table-empty">
                {rows.length ? t("无匹配结果") : t("暂无请求")}
              </div>
            )}
          </div>
          <p className="small muted table-note">
            {visible.length > 1000
              ? t("显示最近 1000 条，共 {count} 条", { count: visible.length })
              : t("{count} 条记录", { count: visible.length })}
          </p>
        </>
      )}
      {selected && (
        <RequestModal
          row={selected}
          current={selected.key.startsWith(`${generation.current}:`)}
          onBlock={block}
          onClose={() => setSelected(null)}
        />
      )}
    </>
  );
}

function RequestRow({ row, onOpen }: { row: Row; onOpen: () => void }) {
  const http = row.http;
  let kind: string;
  let target: React.ReactNode;
  let state: React.ReactNode;
  if (http) {
    const url = (() => {
      try {
        const parsed = new URL(http.url);
        return { host: parsed.host, rest: parsed.pathname + parsed.search };
      } catch {
        return { host: row.host, rest: http.url };
      }
    })();
    kind = http.method;
    target = (
      <>
        <strong>{url.host}</strong>
        <span className="muted">{url.rest}</span>
      </>
    );
    state = http.error ? (
      <span className="danger-text">{http.status ?? t("失败")}</span>
    ) : (
      <span className={(http.status ?? 0) >= 400 ? "danger-text" : ""}>
        {http.status ?? "—"}
      </span>
    );
  } else {
    kind = row.network.toUpperCase();
    target = (
      <>
        <strong>{row.host}</strong>
        <span className="muted">:{row.port}</span>
      </>
    );
    state =
      row.status === "rejected" ? (
        <span className="danger-text">{t("已拦截")}</span>
      ) : row.requests ? (
        <span className="muted">
          {t("{count} 个请求", { count: row.requests })}
        </span>
      ) : (
        <span className="muted">{row.reason ?? t("已关闭")}</span>
      );
  }
  return (
    <tr
      className={`request-row ${row.status}`}
      tabIndex={0}
      onClick={onOpen}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onOpen();
        }
      }}
    >
      <td className="muted">{time(row.time)}</td>
      <td className="request-target">
        <span className="tiny-tag">
          {http?.decrypted ? `${kind} 🔓` : kind}
        </span>
        <span className="request-url">{target}</span>
        {http?.rewrite && (
          <span className="tiny-tag rewrite-tag" title={http.rewrite}>
            {t("已重写")}
          </span>
        )}
      </td>
      <td>{state}</td>
      <td className="muted request-route">
        {row.rule} → {row.chain}
      </td>
      <td className="num">
        {bytes(http ? http.responseSize : row.download + row.upload)}
      </td>
      <td className="num muted">
        {row.status === "rejected" ? "—" : duration(row.duration)}
      </td>
    </tr>
  );
}

function BodyBlock({ body }: { body?: BodyView }) {
  const [pretty, setPretty] = useState(true);
  if (!body || body.size === 0)
    return <p className="muted small">{t("无内容")}</p>;
  let text = body.text;
  if (text !== undefined && pretty) {
    try {
      text = JSON.stringify(JSON.parse(text), null, 2);
    } catch {
      /* not JSON */
    }
  }
  return (
    <div className="body-block">
      <p className="muted small">
        {bytes(body.size)}
        {body.decoded && ` · ${t("已解压")}`}
        {body.truncated && ` · ${t("只保留了开头部分")}`}
        {body.text !== undefined && (
          <button className="text-button" onClick={() => setPretty((p) => !p)}>
            {pretty ? t("原文") : t("格式化")}
          </button>
        )}
      </p>
      <pre>
        {text ??
          `${t("二进制内容（base64）")}\n${(body.base64 ?? "").slice(0, 20000)}`}
      </pre>
    </div>
  );
}

function Headers({ list }: { list?: [string, string][] }) {
  if (!list?.length) return <p className="muted small">{t("无")}</p>;
  return (
    <dl className="header-list">
      {list.map(([name, value], index) => (
        <div key={index}>
          <dt>{name}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  );
}

function RequestModal({
  row,
  current,
  onBlock,
  onClose,
}: {
  row: Row;
  current: boolean;
  onBlock: (host: string) => void;
  onClose: () => void;
}) {
  const [detail, setDetail] = useState<RequestDetail | null>(null);
  const [missing, setMissing] = useState(false);
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!row.http) return;
    if (!current) {
      setMissing(true);
      return;
    }
    void invoke<RequestDetail>("request_detail", { id: row.id })
      .then(setDetail)
      .catch(() => setMissing(true));
  }, [row, current]);
  const http = row.http;
  const copy = (text: string) =>
    void navigator.clipboard?.writeText(text).then(() => {
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    });
  return (
    <Modal
      title={http ? `${http.method} ${row.host}` : `${row.host}:${row.port}`}
      onClose={onClose}
      wide
    >
      <div className="request-detail">
        {http && <p className="request-full-url">{http.url}</p>}
        <dl className="detail-list">
          <div>
            <dt>{t("时间")}</dt>
            <dd>{new Date(row.time).toLocaleString(locale())}</dd>
          </div>
          <div>
            <dt>{t("规则")}</dt>
            <dd>
              {row.rule} → {row.chain}
            </dd>
          </div>
          {row.source && (
            <div>
              <dt>{t("来源")}</dt>
              <dd>{row.source}</dd>
            </div>
          )}
          {http?.status !== undefined && (
            <div>
              <dt>{t("状态码")}</dt>
              <dd>{http.status}</dd>
            </div>
          )}
          {http?.contentType && (
            <div>
              <dt>{t("内容类型")}</dt>
              <dd>{http.contentType}</dd>
            </div>
          )}
          {http?.rewrite && (
            <div>
              <dt>{t("重写")}</dt>
              <dd>{http.rewrite}</dd>
            </div>
          )}
          {(http?.error || row.reason) && (
            <div>
              <dt>{t("结束原因")}</dt>
              <dd>{http?.error ?? row.reason}</dd>
            </div>
          )}
          {row.status !== "rejected" && (
            <div>
              <dt>{t("耗时")}</dt>
              <dd>{duration(row.duration)}</dd>
            </div>
          )}
        </dl>
        <div className="modal-actions request-detail-actions">
          {http && (
            <button className="button secondary" onClick={() => copy(http.url)}>
              <Copy size={15} />
              {copied ? t("已复制") : t("复制 URL")}
            </button>
          )}
          {row.chain !== "REJECT" && (
            <button className="button danger" onClick={() => onBlock(row.host)}>
              <Ban size={15} />
              {t("屏蔽此域名")}
            </button>
          )}
        </div>
        {http && missing && (
          <p className="muted small">
            {t("内核已重启或记录已被清理，详情不可用。")}
          </p>
        )}
        {detail && (
          <>
            <h4>{t("请求头")}</h4>
            <Headers list={detail.requestHeaders} />
            <h4>{t("请求内容")}</h4>
            <BodyBlock body={detail.requestBody} />
            <h4>{t("响应头")}</h4>
            <Headers list={detail.responseHeaders} />
            <h4>{t("响应内容")}</h4>
            <BodyBlock body={detail.responseBody} />
          </>
        )}
      </div>
    </Modal>
  );
}

function RewritePanel({ decrypting }: { decrypting: boolean }) {
  const [status, setStatus] = useState<RewriteStatus | null>(null);
  const [open, setOpen] = useState(false);
  const shown = usePageVisible();
  useEffect(() => {
    const load = () =>
      void invoke<RewriteStatus>("rewrite_status")
        .then(setStatus)
        .catch(() => setStatus(null));
    load();
    if (!shown) return;
    const timer = window.setInterval(load, 5000);
    return () => window.clearInterval(timer);
  }, [shown]);
  if (!status) return null;
  const problems = status.modules.filter(
    (m) => m.error || m.missing.length || m.skipped.length,
  ).length;
  const summary = !decrypting
    ? t("HTTPS 解密未开启，模块不生效")
    : t("{modules} 个模块，{rules} 条规则，已生效 {hits} 次", {
        modules: status.modules.length,
        rules: status.rules,
        hits: status.total,
      });
  return (
    <section className="panel mitm-panel">
      <div className="panel-title">
        <h3>{t("重写模块")}</h3>
        <div className="mitm-title-actions">
          <span className={`small ${decrypting ? "" : "muted"}`}>
            {summary}
            {problems > 0 && ` · ${t("{count} 个有问题", { count: problems })}`}
          </span>
          <button className="text-button" onClick={() => setOpen((o) => !o)}>
            {open ? t("收起") : t("详情")}
          </button>
        </div>
      </div>
      {open && (
        <div className="mitm-body">
          <p className="muted small">
            {t(
              "规则只作用于解密的域名；模块的主机名已加入解密（共 {count} 个）。在设置里添加或移除模块。",
              { count: status.hostnames.length },
            )}
          </p>
          <div className="rewrite-modules">
            {status.modules.map((module) => (
              <div key={module.name} className="small">
                <div className="rewrite-module">
                  <strong>
                    {module.name === "custom" ? t("自定义规则") : module.name}
                  </strong>
                  {module.title && module.title !== module.name && (
                    <span className="muted">{module.title}</span>
                  )}
                  {module.error ? (
                    <span className="danger-text">{module.error}</span>
                  ) : (
                    <span className="muted">
                      {t(
                        "{rules} 条规则 · {scripts} 个脚本 · {hosts} 个主机名 · 生效 {hits} 次",
                        {
                          rules: module.rules,
                          scripts: module.scripts,
                          hosts: module.hostnames,
                          hits: status.hits[module.name] ?? 0,
                        },
                      )}
                    </span>
                  )}
                </div>
                {module.missing.length > 0 && (
                  <p className="danger-text">
                    {t("下载失败：{list}", {
                      list: module.missing.join("、"),
                    })}
                  </p>
                )}
                {module.skipped.length > 0 && (
                  <details>
                    <summary className="muted">
                      {t("{count} 行不支持，已跳过", {
                        count: module.skipped.length,
                      })}
                    </summary>
                    <pre className="rule-preview">
                      {module.skipped
                        .map((s) => `${s.line}: ${s.text}`)
                        .join("\n")}
                    </pre>
                  </details>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}

function BlockConfirm({
  host,
  perform,
  onClose,
}: {
  host: string;
  perform: Perform;
  onClose: () => void;
}) {
  const [suffix, setSuffix] = useState(false);
  const rule = `${suffix ? "DOMAIN-SUFFIX" : "DOMAIN"},${host},REJECT`;
  return (
    <Modal title={t("屏蔽此域名")} onClose={onClose}>
      <p className="small">{t("将添加自定义规则，内核会重新启动以应用：")}</p>
      <pre className="rule-preview">{rule}</pre>
      <label className="rule-check">
        <input
          type="checkbox"
          checked={suffix}
          onChange={(e) => setSuffix(e.target.checked)}
        />
        {t("同时屏蔽它的子域名")}
      </label>
      <div className="modal-actions">
        <button className="button secondary" onClick={onClose}>
          {t("取消")}
        </button>
        <button
          className="button danger"
          onClick={() => {
            onClose();
            void perform(
              async () => {
                const current = await invoke<CustomRules>("custom_rules");
                if (current.rules.includes(rule)) return;
                await invoke("save_custom_rules", {
                  rules: [rule, ...current.rules],
                });
              },
              t("已屏蔽 {host}", { host }),
            );
          }}
        >
          {t("屏蔽")}
        </button>
      </div>
    </Modal>
  );
}

function MitmPanel({
  running,
  settings,
  perform,
}: {
  running: boolean;
  settings: Settings;
  perform: Perform;
}) {
  const mitm = settings.overrides.mitm ?? { enable: false, hostnames: [] };
  const [info, setInfo] = useState<MitmInfo | null>(null);
  const [open, setOpen] = useState(false);
  const [hosts, setHosts] = useState(mitm.hostnames.join("\n"));
  const saved = mitm.hostnames.join("\n");
  useEffect(() => setHosts(saved), [saved]);
  const load = useCallback(
    () =>
      void invoke<MitmInfo>("mitm_info")
        .then(setInfo)
        .catch(() => setInfo(null)),
    [],
  );
  const shown = usePageVisible();
  useEffect(() => {
    load();
    if (!shown || !open) return;
    const timer = window.setInterval(load, 10000);
    return () => window.clearInterval(timer);
  }, [load, shown, open, running]);
  const update = (next: { enable: boolean; hostnames: string[] }) =>
    perform(async () => {
      await invoke("save_settings", {
        settings: {
          ...settings,
          overrides: { ...settings.overrides, mitm: next },
        },
      });
      load();
    });
  const list = (text: string) =>
    text
      .split(/[\n,]/)
      .map((h) => h.trim())
      .filter(Boolean);
  const action = (command: string, success?: string) =>
    void perform(async () => {
      await invoke(command);
      load();
    }, success);
  const ca = info?.ca;
  const core = info?.core;
  const status = !mitm.enable
    ? t("未开启")
    : !ca
      ? t("需要先生成证书")
      : core?.error
        ? core.error
        : !info?.trusted
          ? t("证书未被系统信任")
          : !mitm.hostnames.length && !settings.overrides.rewrite?.enabled
            ? t("还没有填写要解密的域名")
            : t("已开启");
  return (
    <section className="panel mitm-panel">
      <div className="panel-title">
        <h3>
          <KeyRound size={15} /> {t("HTTPS 解密")}
        </h3>
        <div className="mitm-title-actions">
          <span
            className={`small ${mitm.enable && ca && info?.trusted && !core?.error ? "" : "muted"}`}
          >
            {status}
          </span>
          <Toggle
            checked={mitm.enable}
            label={t("HTTPS 解密")}
            onChange={(enable) =>
              void perform(async () => {
                // Turning it on the first time makes the certificate too.
                if (enable && info && !info.ca)
                  await invoke("generate_mitm_ca");
                await update({ ...mitm, enable });
              })
            }
          />
          <button className="text-button" onClick={() => setOpen((o) => !o)}>
            {open ? t("收起") : t("设置")}
          </button>
        </div>
      </div>
      {open && (
        <div className="mitm-body">
          <p className="muted small">
            {t(
              "对下面列出的域名做中间人解密，记录完整的 URL、请求头和内容。需要先生成证书并让系统信任它。使用证书固定（pinning）的应用会拒绝解密，这些域名会自动改为直接转发。只在分析时开启，用完关掉。",
            )}
          </p>
          <Setting
            label={t("CA 证书")}
            text={
              ca
                ? `${ca.name} · SHA-256 ${ca.fingerprint.slice(0, 23)}…`
                : t("还没有证书")
            }
          >
            <div className="service-actions">
              {ca && (
                <span
                  className={`tiny-tag ${info?.trusted ? "" : "danger-text"}`}
                >
                  {info?.trusted ? t("已信任") : t("未信任")}
                </span>
              )}
              <button
                className="button secondary"
                onClick={() => action("generate_mitm_ca", t("已生成新证书"))}
              >
                <RefreshCw size={15} />
                {ca ? t("重新生成") : t("生成证书")}
              </button>
              {ca && !info?.trusted && (
                <button
                  className="button"
                  onClick={() =>
                    action("trust_mitm_ca", t("证书已加入系统信任"))
                  }
                >
                  <ShieldCheck size={15} />
                  {t("安装并信任")}
                </button>
              )}
              {ca && (
                <button
                  className="button secondary"
                  onClick={() =>
                    void perform(async () => {
                      const path = await save({
                        defaultPath: "clyntis-ca.crt",
                        filters: [
                          { name: "Certificate", extensions: ["crt", "pem"] },
                        ],
                      });
                      if (path) await invoke("export_mitm_ca", { path });
                    })
                  }
                >
                  <Download size={15} />
                  {t("导出")}
                </button>
              )}
            </div>
          </Setting>
          <div className="mitm-hosts">
            <label className="field">
              <span>{t("解密的域名（每行一个）")}</span>
              <textarea
                rows={4}
                spellCheck={false}
                value={hosts}
                placeholder={"*.biliapi.net\napi.example.com\n-*.apple.com"}
                onChange={(e) => setHosts(e.target.value)}
              />
            </label>
            <p className="muted small">
              {t(
                "* 匹配任意字符，以 - 开头表示排除。填 * 会解密所有 HTTPS 流量，不建议长期使用。",
              )}
            </p>
            <div className="modal-actions">
              <button
                className="button"
                disabled={list(hosts).join("\n") === saved}
                onClick={() => void update({ ...mitm, hostnames: list(hosts) })}
              >
                {t("保存")}
              </button>
            </div>
          </div>
          {!!core?.bypassed.length && (
            <div className="mitm-bypassed">
              <div className="panel-title">
                <span className="small">
                  {t("拒绝解密、已改为直接转发的域名")}
                </span>
                <button
                  className="text-button"
                  onClick={() => action("clear_mitm_bypass")}
                >
                  {t("重试这些域名")}
                </button>
              </div>
              <p className="muted small">{core.bypassed.join("、")}</p>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
