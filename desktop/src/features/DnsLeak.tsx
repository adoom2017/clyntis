import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Globe2, LoaderCircle, ShieldCheck } from "lucide-react";
import { t } from "../i18n";
import { type DnsLeakAudit, type DnsLeakTest, type LeakProbe } from "../types";

const findingLevelText = {
  risk: t("泄露"),
  warning: t("注意"),
  info: t("提示"),
};
const leakVerdictText = {
  leak: t("存在泄露：本地上游看到了走代理的域名"),
  ok: t("未发现泄露"),
  direct: t("直连，无代理路径可检查"),
  unknown: t("无法判断"),
};
function LeakResolvers({
  title,
  probe,
  verdict,
}: {
  title: string;
  probe: LeakProbe;
  verdict?: DnsLeakTest["verdict"];
}) {
  const status =
    probe.error ??
    (verdict
      ? leakVerdictText[verdict]
      : probe.resolvers.length
        ? t("本地解析由这些服务器完成")
        : t("没有结果"));
  return (
    <div className="leak-probe">
      <div className="leak-probe-title">
        <strong>{title}</strong>
        <span
          className={
            probe.error || verdict === "leak" ? "danger-text" : "muted"
          }
        >
          {status}
        </span>
      </div>
      {probe.resolvers.map((server) => (
        <div key={server.ip} className="leak-server">
          <code>{server.ip}</code>
          <span className="muted">
            {[server.country, server.asn].filter(Boolean).join(" · ")}
          </span>
        </div>
      ))}
    </div>
  );
}
export function DnsLeakPanel({
  running,
  rules,
}: {
  running: boolean;
  rules: string[];
}) {
  const [audit, setAudit] = useState<DnsLeakAudit | null>(null);
  const [test, setTest] = useState<DnsLeakTest | null>(null);
  const [testing, setTesting] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);
  const check = useCallback(() => {
    setFailure(null);
    void invoke<DnsLeakAudit>("dns_leak_audit")
      .then(setAudit)
      .catch((e) => setFailure(String(e)));
  }, []);
  useEffect(() => {
    // Custom rules apply at once while running: review them again.
    if (running) check();
    else setAudit(null);
  }, [running, rules, check]);
  const runTest = async () => {
    setTesting(true);
    setFailure(null);
    try {
      setTest(await invoke<DnsLeakTest>("dns_leak_test"));
      check();
    } catch (e) {
      setFailure(String(e));
    } finally {
      setTesting(false);
    }
  };
  return (
    <section className="panel settings-section dns-leak">
      <div className="panel-title">
        <h3>
          <ShieldCheck size={16} />
          {t("DNS 泄露检测")}
        </h3>
        <button
          className="button secondary"
          disabled={!running || testing}
          onClick={() => void runTest()}
        >
          {testing ? (
            <LoaderCircle className="spin" size={16} />
          ) : (
            <Globe2 size={16} />
          )}
          {testing ? t("检测中…") : t("在线检测")}
        </button>
      </div>
      {!running && <p className="small muted">{t("启动内核后可检测。")}</p>}
      {failure && (
        <p className="inline-error" role="alert">
          {failure}
        </p>
      )}
      {audit && (
        <>
          <p className={audit.leaking ? "danger-text" : "muted small"}>
            {audit.leaking
              ? t("配置检查发现 DNS 泄露风险")
              : audit.findings.length
                ? t("配置检查未发现泄露，但有以下提示")
                : t("配置检查未发现问题")}
          </p>
          {audit.findings.map((finding) => (
            <div key={finding.code} className={`leak-finding ${finding.level}`}>
              <div>
                <span className="leak-level">
                  {findingLevelText[finding.level]}
                </span>
                <strong>{finding.title}</strong>
              </div>
              <p className="small muted">{finding.detail}</p>
              {finding.items.length > 0 && (
                <ul>
                  {finding.items.map((item) => (
                    <li key={item}>
                      <code>{item}</code>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          ))}
        </>
      )}
      {test && (
        <div className="leak-test" aria-label={t("在线检测结果")}>
          <div className="leak-server">
            <strong>{t("出口 IP")}</strong>
            <span>
              {test.exit.length
                ? test.exit
                    .map((e) =>
                      [e.ip, e.country, e.asn].filter(Boolean).join(" · "),
                    )
                    .join("，")
                : t("未知")}
            </span>
          </div>
          <p className="small muted">
            {test.node === "DIRECT"
              ? t(
                  "bash.ws 当前经「{node}」（{matched}）访问，结果反映直连时的情况；让 bash.ws 走代理后再测可检查代理路径。",
                  { node: test.node, matched: test.matched },
                )
              : t("bash.ws 当前经「{node}」（{matched}）访问。", {
                  node: test.node,
                  matched: test.matched,
                })}
          </p>
          <LeakResolvers
            title={t("应用访问时的解析器")}
            probe={test.routed}
            verdict={test.verdict}
          />
          <LeakResolvers
            title={t("内核上游 DNS 的解析器")}
            probe={test.local}
          />
        </div>
      )}
      <p className="hint">
        {t(
          "配置检查在本地完成；在线检测会向 bash.ws 发送随机域名，并暴露出口和解析器的 IP。",
        )}
      </p>
    </section>
  );
}
