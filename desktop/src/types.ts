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
}
export const adblockPresets = [
  {
    id: "awavenue",
    name: "AWAvenue-Ads",
    description: "国内 App 广告接口，约 1,000 条，误杀少",
  },
  {
    id: "anti-ad",
    name: "anti-AD",
    description: "覆盖面广，以国内为主，约 10 万条",
  },
  {
    id: "adguard-dns",
    name: "AdGuard DNS filter",
    description: "偏海外的广告与追踪，约 18 万条",
  },
] as const;
export const defaultAdblock: AdblockSettings = {
  enabled: true,
  presets: ["awavenue"],
  custom: [],
  allow: [],
};
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
  state: "connecting" | "running" | "error";
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
  connecting: "连接中",
  running: "已连接",
  error: "连接失败",
};
export function peerPathText(peer: TailscalePeer): string {
  if (peer.path === "direct")
    return peer.rtt_ms == null ? "直连" : `直连 ${peer.rtt_ms} ms`;
  if (peer.path === "derp") return peer.derp ? `中继 ${peer.derp}` : "中继";
  return peer.online ? "空闲" : "离线";
}
/** One line for node cards: what matters most for this kind of node. */
export function nodeSummary(status: NodeStatus | undefined, type?: string) {
  if (!status) return type ?? "—";
  const ts = status.tailscale;
  if (ts) {
    if (ts.state !== "running") return tailscaleStateText[ts.state];
    const online = ts.peers.filter((p) => p.online).length;
    const direct = ts.peers.filter((p) => p.path === "direct").length;
    return `已连接 · ${online} 台在线${direct ? ` · ${direct} 直连` : ""}`;
  }
  const parts = [status.type];
  if (status.server) parts.push(status.server);
  if (status.connections) parts.push(`${status.connections} 连接`);
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
export const ruleTypes: { type: string; label: string; placeholder: string }[] =
  [
    { type: "DOMAIN-SUFFIX", label: "域名后缀", placeholder: "example.com" },
    { type: "DOMAIN", label: "完整域名", placeholder: "www.example.com" },
    { type: "DOMAIN-KEYWORD", label: "域名关键字", placeholder: "example" },
    { type: "IP-CIDR", label: "IPv4 段", placeholder: "10.0.0.0/8" },
    { type: "IP-CIDR6", label: "IPv6 段", placeholder: "2001:db8::/32" },
    { type: "GEOSITE", label: "GeoSite", placeholder: "cn" },
    { type: "GEOIP", label: "GeoIP", placeholder: "CN" },
    { type: "DST-PORT", label: "目标端口", placeholder: "443 或 8000-9000" },
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
    launchAtLogin: false,
    autoConnect: false,
    subscriptionIntervalHours: 24,
    overrides: {},
  },
};
export const statusText: Record<Status, string> = {
  stopped: "未连接",
  starting: "正在连接",
  running: "已连接",
  stopping: "正在停止",
  recovering: "正在恢复",
  failed: "连接失败",
};
export const modeText: Record<Mode, string> = {
  rule: "规则",
  global: "全局",
  direct: "直连",
};
export const captureText: Record<Capture, string> = {
  manual: "手动代理",
  system: "系统代理",
  tun: "TUN 模式",
};
export function bytes(value: number): string {
  if (!Number.isFinite(value) || value <= 0) return "0 B";
  const unit = Math.min(Math.floor(Math.log(value) / Math.log(1024)), 4);
  return `${(value / 1024 ** unit).toFixed(unit === 0 ? 0 : 1)} ${["B", "KB", "MB", "GB", "TB"][unit]}`;
}
