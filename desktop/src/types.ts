import { t, tx, type Language } from "./i18n";

export type Capture = "manual" | "system" | "tun";
export type Mode = "rule" | "global" | "direct";
export type Status =
  | "stopped"
  | "starting"
  | "running"
  | "stopping"
  | "recovering"
  | "failed";
export interface Settings {
  capture: Capture;
  mixedPort: number;
  allowLan: boolean;
  autoDns: boolean;
  tunInterface: string | null;
  theme: "system" | "light" | "dark";
  language: Language;
  launchAtLogin: boolean;
  autoConnect: boolean;
  subscriptionIntervalHours: number;
  overrides: Overrides;
}
export type LogLevel = "debug" | "info" | "warning" | "error" | "silent";
/** Replaces the profile's value when set; absent keeps the profile's own. */
export interface Overrides {
  logLevel?: LogLevel | null;
  ipv6?: boolean | null;
  sniffing?: boolean | null;
  tailscale?: boolean | null;
  adblock?: AdblockSettings | null;
}
export type AdListFormat = "clash" | "hosts" | "adguard";
export interface AdList {
  name: string;
  url: string;
  format: AdListFormat;
}
/** Ad blocking settings; the core expands presets and merges them. */
export interface AdblockSettings {
  enabled: boolean;
  presets: string[];
  custom: AdList[];
  allow: string[];
  /** Refuse HTTPDNS and encrypted-DNS endpoints that bypass DNS filtering. */
  blockHttpdns?: boolean;
  /** Reject QUIC to an address without a name, so apps retry over TCP. */
  quicFallback?: boolean;
  /** How DNS refuses a blocked name. */
  dnsAnswer?: "nxdomain" | "null";
}
export const adblockPresets = [
  {
    id: "awavenue",
    name: "AWAvenue-Ads",
    get description() {
      return t("国内 App 广告接口，约 1,000 条，误杀少");
    },
  },
  {
    id: "anti-ad",
    name: "anti-AD",
    get description() {
      return t("覆盖面广，以国内为主，约 10 万条");
    },
  },
  {
    id: "adguard-dns",
    name: "AdGuard DNS filter",
    get description() {
      return t("偏海外的广告与追踪，约 18 万条");
    },
  },
] as const;
export const defaultAdblock: AdblockSettings = {
  enabled: true,
  presets: ["awavenue"],
  custom: [],
  allow: [],
  blockHttpdns: true,
  quicFallback: true,
  dnsAnswer: "nxdomain",
};
/** The core's `/network`: the profile's networks the device is on. */
export interface NetworkStatus {
  defined: boolean;
  networks: string[];
  override: string | null;
  info: {
    type?: string;
    ssid?: string;
    addresses: string[];
    gateways: string[];
  };
}
export interface AdblockStatus {
  enabled: boolean;
  entries: number;
  since: number;
  total: number;
  dns: number;
  connections: number;
  domains: number;
  lists: {
    name: string;
    entries: number;
    updated: number | null;
    error: string | null;
  }[];
  top: { domain: string; count: number }[];
  recent: { time: number; domain: string; via: "dns" | "connection" }[];
}
export interface ProfileSummary {
  id: string;
  name: string;
  source: string;
  subscription: boolean;
  encrypted: boolean;
  pending: boolean;
  lastChecked: number;
  lastError: string | null;
}
/** A Tencent COS object a profile is published to. */
export interface PublishTarget {
  bucket: string;
  region: string;
  key: string;
}
export interface ImportResult {
  profile: ProfileSummary;
  warnings: { path: string; reason: string }[];
}
export interface Profile extends Omit<
  ProfileSummary,
  "pending" | "source" | "subscription" | "encrypted"
> {
  yaml: string;
  pending: string | null;
  previous: string | null;
  url: string | null;
  mode: Mode;
}
export interface Log {
  type: string;
  payload: string;
  time: number;
}
export interface Snapshot {
  status: Status;
  error: string | null;
  selected: string | null;
  mode: Mode;
  settings: Settings;
  profiles: ProfileSummary[];
  serviceStatus: string;
  logs: Log[];
}
export interface Traffic {
  up: number;
  down: number;
}
export interface Proxy {
  name: string;
  type: string;
  all?: string[];
  now?: string;
  history: { delay: number }[];
  status?: NodeStatus;
}
/** Per-proxy status from the core: the last delay test and kind details. */
export interface NodeStatus {
  type: string;
  connections: number;
  delay: number | null;
  error: string | null;
  checked: number | null;
  server?: string;
  network?: string;
  security?: string;
  flow?: string | null;
  udp?: boolean;
  tailscale?: TailscaleStatus;
}
export interface TailscaleStatus {
  state: "connecting" | "running" | "error" | "disabled";
  error: string | null;
  name: string | null;
  addresses: string[];
  home_derp: string | null;
  endpoints: string[];
  peers: TailscalePeer[];
}
export interface TailscalePeer {
  name: string;
  address: string | null;
  os: string | null;
  online: boolean | null;
  path: "direct" | "derp" | "idle";
  direct: string | null;
  rtt_ms: number | null;
  derp: string | null;
  exit_node: boolean;
}
export const tailscaleStateText: Record<TailscaleStatus["state"], string> = {
  get connecting() {
    return t("连接中");
  },
  get running() {
    return t("已连接");
  },
  get error() {
    return t("连接失败");
  },
  get disabled() {
    return t("已关闭");
  },
};
export function peerPathText(peer: TailscalePeer): string {
  if (peer.path === "direct")
    return peer.rtt_ms == null
      ? t("直连")
      : t("直连 {rtt} ms", { rtt: peer.rtt_ms });
  if (peer.path === "derp")
    return peer.derp ? t("中继 {region}", { region: peer.derp }) : t("中继");
  return peer.online ? t("空闲") : t("离线");
}
/** One line for node cards: what matters most for this kind of node. */
export function nodeSummary(status: NodeStatus | undefined, type?: string) {
  if (!status) return type ?? "—";
  const ts = status.tailscale;
  if (ts) {
    if (ts.state !== "running") return tailscaleStateText[ts.state];
    const online = ts.peers.filter((p) => p.online).length;
    const direct = ts.peers.filter((p) => p.path === "direct").length;
    const summary = t("已连接 · {online} 台在线", { online });
    return direct ? `${summary} · ${t("{direct} 直连", { direct })}` : summary;
  }
  const parts = [status.type];
  if (status.server) parts.push(status.server);
  if (status.connections)
    parts.push(t("{count} 连接", { count: status.connections }));
  return parts.join(" · ");
}
export interface Connection {
  id: string;
  metadata: { host: string; port: number };
  network: string;
  chains: string[];
  upload: number;
  download: number;
  start: string;
}
export interface CustomRules {
  rules: string[];
  /** Targets the selected profile offers: DIRECT, REJECT, groups, proxies. */
  targets: string[];
  /** Rules the selected profile cannot use, with the reason. */
  skipped: { rule: string; reason: string }[];
  profile: string | null;
}
/** How the core would route a domain or address now (`POST /rules/test`). */
export interface RouteTest {
  host: string;
  port: number;
  network: "tcp" | "udp";
  mode: Mode;
  /** The address IP rules saw; null when none was needed or resolving failed. */
  ip: string | null;
  /** The matching rule as written; null for ad blocking, modes and fallback. */
  rule: string | null;
  /** Zero-based position among the active rules (custom rules come first). */
  index: number | null;
  /** Short form as in the connection log: `DomainSuffix(x)`, `Adblock`… */
  matched: string;
  /** The rule's target, then each group's selection down to `node`. */
  chain: string[];
  node: string;
  /** A rule resolved the name through the core's upstreams before matching. */
  resolved_locally: boolean;
}
export interface DnsLeakFinding {
  level: "risk" | "warning" | "info";
  code: string;
  title: string;
  detail: string;
  items: string[];
}
/** Offline review of the running configuration (`GET /dns/leak`). */
export interface DnsLeakAudit {
  leaking: boolean;
  findings: DnsLeakFinding[];
}
export interface LeakServer {
  ip: string;
  country: string;
  asn: string;
}
export interface LeakProbe {
  resolvers: LeakServer[];
  error: string | null;
}
/** Online test through bash.ws (`POST /dns/leak/test`). */
export interface DnsLeakTest {
  exit: LeakServer[];
  /** Node and rule bash.ws traffic uses; the test reflects that route. */
  node: string;
  matched: string;
  /** Whether proxied names reached the core's own upstreams: `direct` when
   * bash.ws is not proxied, `unknown` when a probe saw no resolvers. */
  verdict: "leak" | "ok" | "direct" | "unknown";
  /** Resolvers seen when connecting like an app (through the rules). */
  routed: LeakProbe;
  /** Resolvers behind the core's own upstreams. */
  local: LeakProbe;
}
export const ruleTypes: { type: string; label: string; placeholder: string }[] =
  [
    {
      type: "DOMAIN-SUFFIX",
      get label() {
        return t("域名后缀");
      },
      placeholder: "example.com",
    },
    {
      type: "DOMAIN",
      get label() {
        return t("完整域名");
      },
      placeholder: "www.example.com",
    },
    {
      type: "DOMAIN-KEYWORD",
      get label() {
        return t("域名关键字");
      },
      placeholder: "example",
    },
    {
      type: "IP-CIDR",
      get label() {
        return t("IPv4 段");
      },
      placeholder: "10.0.0.0/8",
    },
    {
      type: "IP-CIDR6",
      get label() {
        return t("IPv6 段");
      },
      placeholder: "2001:db8::/32",
    },
    { type: "GEOSITE", label: "GeoSite", placeholder: "cn" },
    { type: "GEOIP", label: "GeoIP", placeholder: "CN" },
    {
      type: "DST-PORT",
      get label() {
        return t("目标端口");
      },
      get placeholder() {
        return t("443 或 8000-9000");
      },
    },
    {
      type: "NETWORK-NAME",
      get label() {
        return t("所在网络");
      },
      get placeholder() {
        return t("配置 networks 中的名称，如 home");
      },
    },
  ];
/** Splits `TYPE,VALUE,TARGET[,no-resolve]` for display; logical rules stay whole. */
export function splitRule(rule: string) {
  const fields = rule.split(",");
  const noResolve = fields.at(-1)?.trim() === "no-resolve";
  if (noResolve) fields.pop();
  const type = fields[0]?.trim() ?? "";
  const target = fields.length > 1 ? fields.pop()!.trim() : "";
  return { type, value: fields.slice(1).join(","), target, noResolve };
}
export interface Connections {
  connections: Connection[];
  uploadTotal: number;
  downloadTotal: number;
}
export const initial: Snapshot = {
  status: "stopped",
  error: null,
  selected: null,
  mode: "rule",
  profiles: [],
  logs: [],
  serviceStatus: "checking",
  settings: {
    capture: "manual",
    mixedPort: 7890,
    allowLan: false,
    autoDns: true,
    tunInterface: null,
    theme: "system",
    language: "system",
    launchAtLogin: false,
    autoConnect: false,
    subscriptionIntervalHours: 24,
    overrides: {},
  },
};
export const statusText: Record<Status, string> = {
  get stopped() {
    return t("未连接");
  },
  get starting() {
    return t("正在连接");
  },
  get running() {
    return t("已连接");
  },
  get stopping() {
    return t("正在停止");
  },
  get recovering() {
    return t("正在恢复");
  },
  get failed() {
    return t("连接失败");
  },
};
export const modeText: Record<Mode, string> = {
  get rule() {
    return tx("mode", "规则");
  },
  get global() {
    return t("全局");
  },
  get direct() {
    return t("直连");
  },
};
export const captureText: Record<Capture, string> = {
  get manual() {
    return t("手动代理");
  },
  get system() {
    return t("系统代理");
  },
  get tun() {
    return t("TUN 模式");
  },
};
export function bytes(value: number): string {
  if (!Number.isFinite(value) || value <= 0) return "0 B";
  const unit = Math.min(Math.floor(Math.log(value) / Math.log(1024)), 4);
  return `${(value / 1024 ** unit).toFixed(unit === 0 ? 0 : 1)} ${["B", "KB", "MB", "GB", "TB"][unit]}`;
}
