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
}
export interface ProfileSummary {
  id: string;
  name: string;
  source: string;
  pending: boolean;
  lastChecked: number;
  lastError: string | null;
}
export interface ImportResult {
  profile: ProfileSummary;
  warnings: { path: string; reason: string }[];
}
export interface Profile extends Omit<ProfileSummary, "pending" | "source"> {
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
    autoDns: false,
    tunInterface: null,
    theme: "system",
    launchAtLogin: false,
    autoConnect: false,
    subscriptionIntervalHours: 24,
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
