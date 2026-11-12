import { useEffect, useState, type ReactNode } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  LoaderCircle,
  Plus,
  Route,
  Search,
  Trash2,
  ListFilter,
  ChevronUp,
  ChevronDown,
  PencilLine,
} from "lucide-react";
import { t } from "../i18n";
import {
  type CustomRules,
  type RouteTest,
  ruleTypes,
  splitRule,
} from "../types";
import { Empty, Modal } from "../components/common";
import { DnsLeakPanel } from "../features/DnsLeak";

export function RulesPage({
  busy,
  running,
  confirm,
}: {
  busy: boolean;
  running: boolean;
  confirm: (modal: ReactNode) => void;
}) {
  const [data, setData] = useState<CustomRules | null>(null);
  const [type, setType] = useState(ruleTypes[0].type);
  const [value, setValue] = useState("");
  const [target, setTarget] = useState("");
  const [noResolve, setNoResolve] = useState(false);
  const [saving, setSaving] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);
  useEffect(() => {
    void invoke<CustomRules>("custom_rules")
      .then((next) => {
        setData(next);
        setTarget((current) => current || next.targets[0] || "DIRECT");
      })
      .catch((e) => setFailure(String(e)));
  }, []);
  const save = async (rules: string[]) => {
    setSaving(true);
    setFailure(null);
    try {
      setData(await invoke<CustomRules>("save_custom_rules", { rules }));
      return true;
    } catch (e) {
      setFailure(String(e));
      return false;
    } finally {
      setSaving(false);
    }
  };
  if (!data) return failure ? <p className="inline-error">{failure}</p> : null;
  const ip = type === "IP-CIDR" || type === "IP-CIDR6" || type === "GEOIP";
  const placeholder = ruleTypes.find((rule) => rule.type === type)?.placeholder;
  const add = async () => {
    const rule = [
      type,
      value.trim(),
      target,
      ...(ip && noResolve ? ["no-resolve"] : []),
    ].join(",");
    if (await save([rule, ...data.rules])) setValue("");
  };
  const move = (index: number, delta: number) => {
    const rules = [...data.rules];
    const [rule] = rules.splice(index, 1);
    rules.splice(index + delta, 0, rule);
    void save(rules);
  };
  const skipped = new Map(data.skipped.map((s) => [s.rule, s.reason]));
  const disabled = busy || saving;
  return (
    <>
      <h3 className="settings-heading">{t("自定义规则")}</h3>
      <section className="panel settings-section rule-form">
        <form
          onSubmit={(event) => {
            event.preventDefault();
            void add();
          }}
        >
          <select
            aria-label={t("规则类型")}
            value={type}
            onChange={(e) => setType(e.target.value)}
          >
            {ruleTypes.map((rule) => (
              <option key={rule.type} value={rule.type}>
                {rule.label}
              </option>
            ))}
          </select>
          <input
            aria-label={t("规则值")}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder={placeholder}
            spellCheck={false}
            autoComplete="off"
          />
          <select
            aria-label={t("目标")}
            value={target}
            onChange={(e) => setTarget(e.target.value)}
          >
            {data.targets.map((target) => (
              <option key={target}>{target}</option>
            ))}
          </select>
          {ip && (
            <label className="rule-check">
              <input
                type="checkbox"
                checked={noResolve}
                onChange={(e) => setNoResolve(e.target.checked)}
              />
              {t("不解析域名")}
            </label>
          )}
          <button
            className="button primary"
            disabled={disabled || !value.trim()}
          >
            {saving ? (
              <LoaderCircle className="spin" size={16} />
            ) : (
              <Plus size={16} />
            )}
            {t("添加")}
          </button>
        </form>
      </section>
      {failure && (
        <p className="inline-error" role="alert">
          {failure}
        </p>
      )}
      <div className="toolbar">
        <span className="muted small">
          {t("{count} 条规则 · 优先于配置中的规则，按顺序匹配", {
            count: data.rules.length,
          })}
          {running ? ` · ${t("修改后立即生效")}` : ""}
        </span>
        <button
          className="button secondary"
          disabled={disabled}
          onClick={() =>
            confirm(
              <BulkRules
                rules={data.rules}
                onClose={() => confirm(null)}
                onSave={async (rules) => {
                  const ok = await save(rules);
                  if (ok) confirm(null);
                  return ok;
                }}
              />,
            )
          }
        >
          <PencilLine size={16} />
          {t("批量编辑")}
        </button>
      </div>
      {!data.rules.length ? (
        <Empty
          icon={<ListFilter />}
          title={t("还没有自定义规则")}
          text={t("自定义规则对所有配置生效，并且优先于配置自带的规则。")}
        />
      ) : (
        <div className="panel table-wrap">
          <table className="rule-table">
            <thead>
              <tr>
                <th>{t("类型")}</th>
                <th>{t("值")}</th>
                <th>{t("目标")}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {data.rules.map((rule, index) => {
                const parts = splitRule(rule);
                const reason = skipped.get(rule);
                return (
                  <tr key={`${index}-${rule}`}>
                    <td>
                      <span className="tiny-tag">
                        {ruleTypes.find((rule) => rule.type === parts.type)
                          ?.label ?? parts.type}
                      </span>
                    </td>
                    <td>
                      <strong>{parts.value}</strong>
                      {parts.noResolve && (
                        <span className="chain">{t("不解析域名")}</span>
                      )}
                      {reason && (
                        <span className="chain danger">
                          {t("{reason}，当前配置下不生效", { reason })}
                        </span>
                      )}
                    </td>
                    <td>{parts.target}</td>
                    <td className="rule-actions">
                      <button
                        className="icon-button"
                        aria-label={t("上移 {rule}", { rule })}
                        disabled={disabled || index === 0}
                        onClick={() => move(index, -1)}
                      >
                        <ChevronUp size={15} />
                      </button>
                      <button
                        className="icon-button"
                        aria-label={t("下移 {rule}", { rule })}
                        disabled={disabled || index === data.rules.length - 1}
                        onClick={() => move(index, 1)}
                      >
                        <ChevronDown size={15} />
                      </button>
                      <button
                        className="icon-button danger"
                        aria-label={t("删除 {rule}", { rule })}
                        disabled={disabled}
                        onClick={() =>
                          void save(data.rules.filter((_, i) => i !== index))
                        }
                      >
                        <Trash2 size={15} />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {data.profile && (
        <p className="hint">
          {t(
            "目标列表来自当前配置「{profile}」；切换到没有该代理组的配置时，对应规则会被跳过。",
            { profile: data.profile },
          )}
        </p>
      )}
      <h3 className="settings-heading spaced">{t("诊断")}</h3>
      <RouteTester running={running} customRules={data.rules} />
      <DnsLeakPanel running={running} rules={data.rules} />
    </>
  );
}
const routeMatchText: Record<string, string> = {
  Adblock: t("去广告拦截（优先于所有规则）"),
  "Adblock(HTTPDNS)": t("去广告：HTTPDNS / 加密 DNS 入口"),
  "Adblock(IP)": t("去广告：列表中的 IP"),
  "Adblock(QUIC)": t("去广告：没有域名的 QUIC，回退到 TCP"),
  "Mode(Global)": t("全局模式"),
  "Mode(Direct)": t("直连模式"),
  Fallback: t("没有规则匹配，默认直连"),
};
function RouteTester({
  running,
  customRules,
}: {
  running: boolean;
  customRules: string[];
}) {
  const [target, setTarget] = useState("");
  const [network, setNetwork] = useState<"tcp" | "udp">("tcp");
  const [testing, setTesting] = useState(false);
  const [result, setResult] = useState<RouteTest | null>(null);
  const [failure, setFailure] = useState<string | null>(null);
  const test = async () => {
    setTesting(true);
    setFailure(null);
    try {
      setResult(
        await invoke<RouteTest>("test_route", {
          target: target.trim(),
          network,
        }),
      );
    } catch (e) {
      setResult(null);
      setFailure(String(e));
    } finally {
      setTesting(false);
    }
  };
  return (
    <section className="panel settings-section route-test">
      <div className="panel-title">
        <h3>
          <Route size={16} />
          {t("路由测试")}
        </h3>
      </div>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          void test();
        }}
      >
        <input
          aria-label={t("测试目标")}
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder={t("测试域名或 IP，如 www.google.com、8.8.8.8:53")}
          spellCheck={false}
          autoComplete="off"
        />
        <select
          aria-label={t("网络")}
          value={network}
          onChange={(e) => setNetwork(e.target.value as "tcp" | "udp")}
        >
          <option value="tcp">TCP</option>
          <option value="udp">UDP</option>
        </select>
        <button
          className="button secondary"
          disabled={!running || testing || !target.trim()}
          title={running ? undefined : t("启动内核后可测试")}
        >
          {testing ? (
            <LoaderCircle className="spin" size={16} />
          ) : (
            <Search size={16} />
          )}
          {t("测试")}
        </button>
      </form>
      {!running && <p className="small muted">{t("启动内核后可测试路由。")}</p>}
      {failure && (
        <p className="inline-error" role="alert">
          {failure}
        </p>
      )}
      {result && (
        <dl className="route-result" aria-label={t("路由测试结果")}>
          <dt>{t("目标")}</dt>
          <dd>
            {result.host.includes(":") ? `[${result.host}]` : result.host}:
            {result.port} · {result.network.toUpperCase()}
            {result.ip && result.ip !== result.host && (
              <span className="chain">
                {t("解析为 {ip}", { ip: result.ip })}
              </span>
            )}
          </dd>
          <dt>{t("匹配规则")}</dt>
          <dd>
            {result.rule ? (
              <>
                <strong>{result.rule}</strong>
                <span className="chain">
                  {t("第 {index} 条", { index: (result.index ?? 0) + 1 })}
                  {customRules.includes(result.rule)
                    ? ` · ${t("自定义规则")}`
                    : ""}
                </span>
              </>
            ) : (
              <strong>
                {routeMatchText[result.matched] ?? result.matched}
              </strong>
            )}
          </dd>
          <dt>{t("出站节点")}</dt>
          <dd>
            <strong
              className={result.node === "REJECT" ? "danger-text" : undefined}
            >
              {result.node}
            </strong>
            {result.chain.length > 1 && (
              <span className="chain">{result.chain.join(" → ")}</span>
            )}
            {result.resolved_locally &&
              result.node !== "DIRECT" &&
              result.node !== "REJECT" && (
                <span className="chain danger">
                  {t("匹配前已在本地解析域名，存在 DNS 泄露")}
                </span>
              )}
          </dd>
        </dl>
      )}
    </section>
  );
}
function BulkRules({
  rules,
  onClose,
  onSave,
}: {
  rules: string[];
  onClose: () => void;
  onSave: (rules: string[]) => Promise<boolean>;
}) {
  const [text, setText] = useState(rules.join("\n"));
  const [saving, setSaving] = useState(false);
  return (
    <Modal title={t("批量编辑规则")} onClose={onClose} wide>
      <p className="small muted">
        {t(
          "每行一条，格式为「类型,值,目标」，越靠前优先级越高。保存时会校验每一条。",
        )}
      </p>
      <textarea
        className="yaml-editor"
        aria-label={t("自定义规则")}
        value={text}
        onChange={(e) => setText(e.target.value)}
        spellCheck={false}
        placeholder={
          "DOMAIN-SUFFIX,example.com,DIRECT\nIP-CIDR,10.0.0.0/8,DIRECT,no-resolve"
        }
      />
      <div className="modal-actions">
        <button className="button secondary" onClick={onClose}>
          {t("取消")}
        </button>
        <button
          className="button primary"
          disabled={saving}
          onClick={() => {
            setSaving(true);
            const lines = text
              .split("\n")
              .map((l) => l.trim())
              .filter((l) => l && !l.startsWith("#"));
            void onSave(lines).finally(() => setSaving(false));
          }}
        >
          {saving && <LoaderCircle className="spin" size={16} />}
          {t("保存")}
        </button>
      </div>
    </Modal>
  );
}
