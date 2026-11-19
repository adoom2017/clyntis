import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "../src/App";
import { Editor } from "../src/components/Editor";
import { Modal } from "../src/components/common";
import { useState } from "react";
import { bytes, initial } from "../src/types";

const { invoke, listen, open, save } = vi.hoisted(() => ({
  invoke: vi.fn(),
  listen: vi.fn(),
  open: vi.fn(),
  save: vi.fn(),
}));
vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/api/event", () => ({ listen }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open, save }));
beforeEach(() => {
  vi.clearAllMocks();
  listen.mockResolvedValue(vi.fn());
  invoke.mockResolvedValue(structuredClone(initial));
});
afterEach(cleanup);
describe("desktop workflows", () => {
  it("explains system authorization while updating the helper", async () => {
    invoke.mockResolvedValue({
      ...structuredClone(initial),
      serviceStatus: "updating",
    });
    render(<App />);
    expect(await screen.findByRole("status")).toHaveTextContent(
      "虚拟网卡、路由、DNS 和系统代理",
    );
    expect(screen.getByRole("status")).toHaveTextContent("恢复网络设置");
  });

  it("does not connect without a profile and offers an import path", async () => {
    render(<App />);
    await waitFor(() => expect(invoke).toHaveBeenCalledWith("snapshot"));
    expect(screen.getByRole("button", { name: "启动连接" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "添加配置" }));
    expect(screen.getByText("还没有配置")).toBeInTheDocument();
  });
  it("imports only after the native file dialog returns a selection", async () => {
    open.mockResolvedValue(null);
    render(<App />);
    await waitFor(() => expect(invoke).toHaveBeenCalledWith("snapshot"));
    fireEvent.click(screen.getByRole("button", { name: "配置" }));
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "导入文件" })).toBeEnabled(),
    );
    fireEvent.click(screen.getByRole("button", { name: "导入文件" }));
    await waitFor(() => expect(open).toHaveBeenCalled());
    expect(
      invoke.mock.calls.some(([command]) => command === "import_profile"),
    ).toBe(false);
  });
  it("shows explicit permission errors instead of pretending to connect", async () => {
    invoke.mockImplementation(async (command) => {
      if (command === "start") throw "辅助服务不可用";
      return {
        ...initial,
        selected: "profile-id",
        profiles: [
          {
            id: "profile-id",
            name: "测试配置",
            source: "本地文件",
            pending: false,
            lastChecked: 0,
            lastError: null,
          },
        ],
      };
    });
    render(<App />);
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "启动连接" })).toBeEnabled(),
    );
    fireEvent.click(screen.getByRole("button", { name: "启动连接" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "辅助服务不可用",
    );
    expect(screen.getAllByText("未连接").length).toBeGreaterThan(0);
  });
  it("shows skipped items after importing a new compatible profile", async () => {
    open.mockResolvedValue("/tmp/mixed.yaml");
    invoke.mockImplementation(async (command) => {
      if (command === "import_profile")
        return {
          profile: { id: "new-id", name: "mixed" },
          warnings: [{ path: "proxies[1]", reason: "不支持的协议，已跳过" }],
        };
      return structuredClone(initial);
    });
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "配置" }));
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "导入文件" })).toBeEnabled(),
    );
    fireEvent.click(screen.getByRole("button", { name: "导入文件" }));
    expect(
      await screen.findByRole("dialog", { name: "导入完成" }),
    ).toHaveTextContent("跳过 1 项不兼容内容");
    expect(screen.getByText("proxies[1]")).toBeInTheDocument();
    expect(screen.getByText("不支持的协议，已跳过")).toBeInTheDocument();
    expect(invoke).toHaveBeenCalledWith("import_profile", {
      path: "/tmp/mixed.yaml",
    });
    fireEvent.click(screen.getByRole("button", { name: "知道了" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
  it("keeps network takeover and autostart off by default", async () => {
    render(<App />);
    await waitFor(() => expect(invoke).toHaveBeenCalledWith("snapshot"));
    fireEvent.click(screen.getByRole("button", { name: "设置" }));
    expect(screen.getByRole("switch", { name: "登录时启动" })).toHaveAttribute(
      "aria-checked",
      "false",
    );
    expect(
      screen.getByRole("switch", { name: "打开应用后自动连接" }),
    ).toHaveAttribute("aria-checked", "false");
    expect(
      screen.getByRole("switch", { name: "允许局域网访问" }),
    ).toHaveAttribute("aria-checked", "false");
  });
  it("keeps the compatibility report visible after adding a subscription", async () => {
    invoke.mockImplementation(async (command) => {
      if (command === "add_subscription")
        return {
          profile: { id: "subscription-id", name: "日常订阅" },
          warnings: [{ path: "unknown", reason: "不支持的字段，已跳过" }],
        };
      return structuredClone(initial);
    });
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "配置" }));
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "添加订阅" })).toBeEnabled(),
    );
    fireEvent.click(screen.getByRole("button", { name: "添加订阅" }));
    fireEvent.change(screen.getByLabelText("配置名称"), {
      target: { value: "日常订阅" },
    });
    fireEvent.change(screen.getByLabelText("订阅 URL"), {
      target: { value: "https://example.com/sub" },
    });
    fireEvent.click(screen.getByRole("button", { name: "添加" }));
    expect(
      await screen.findByRole("dialog", { name: "导入完成" }),
    ).toHaveTextContent("日常订阅");
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "导入文件" })).toBeEnabled(),
    );
    expect(screen.getByRole("dialog", { name: "导入完成" })).toHaveTextContent(
      "unknown",
    );
  });
  it("keeps unsaved settings when the backend pushes other changes", async () => {
    const handlers: Record<string, (event: { payload: unknown }) => void> = {};
    listen.mockImplementation(async (event: string, handler) => {
      handlers[event] = handler;
      return vi.fn();
    });
    render(<App />);
    await waitFor(() => expect(invoke).toHaveBeenCalledWith("snapshot"));
    fireEvent.click(screen.getByRole("button", { name: "设置" }));
    fireEvent.change(screen.getByDisplayValue("7890"), {
      target: { value: "7891" },
    });
    act(() =>
      handlers.state({
        payload: {
          ...structuredClone(initial),
          settings: { ...initial.settings, capture: "tun" },
        },
      }),
    );
    expect(screen.getByDisplayValue("7891")).toBeInTheDocument();
    expect(screen.getByDisplayValue("TUN 模式")).toBeInTheDocument();
  });
  it.each(["before navigation", "after navigation"])(
    "offers subscription refresh only for subscription profiles (snapshot %s)",
    async (arrival) => {
      const profile = {
        pending: false,
        lastChecked: 0,
        lastError: null,
      };
      const snapshot = {
        ...structuredClone(initial),
        profiles: [
          {
            ...profile,
            id: "a",
            name: "本地",
            source: "本地文件",
            subscription: false,
          },
          {
            ...profile,
            id: "b",
            name: "订阅",
            source: "sub.example.com",
            subscription: true,
          },
        ],
      };
      let resolveSnapshot!: (value: typeof snapshot) => void;
      const snapshotRequest = new Promise<typeof snapshot>((resolve) => {
        resolveSnapshot = resolve;
      });
      invoke.mockImplementation(async (command) =>
        command === "snapshot" ? snapshotRequest : null,
      );
      // Settle listener registration and control snapshot delivery explicitly so
      // this assertion does not race startup through findByRole's timer polling.
      await act(async () => {
        render(<App />);
      });
      expect(invoke).toHaveBeenCalledWith("snapshot");
      const deliverSnapshot = () =>
        act(async () => {
          resolveSnapshot(snapshot);
        });
      if (arrival === "before navigation") await deliverSnapshot();
      fireEvent.click(screen.getByRole("button", { name: "配置" }));
      if (arrival === "after navigation") await deliverSnapshot();

      const refresh = screen.getByRole("button", { name: "更新 订阅" });
      expect(refresh).toBeEnabled();
      expect(
        screen.queryByRole("button", { name: "更新 本地" }),
      ).not.toBeInTheDocument();
      await act(async () => {
        fireEvent.click(refresh);
      });
      expect(invoke).toHaveBeenCalledWith("update_subscription", { id: "b" });
    },
  );
  it("asks for a password before importing an encrypted file", async () => {
    open.mockResolvedValue("/tmp/secret.txt");
    invoke.mockImplementation(async (command, args) => {
      if (command === "inspect_profile_file") return { encrypted: true };
      if (command === "import_profile") {
        if (args.password !== "right") throw "解密失败，请检查密码";
        return { profile: { id: "n", name: "secret" }, warnings: [] };
      }
      return structuredClone(initial);
    });
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "配置" }));
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "导入文件" })).toBeEnabled(),
    );
    fireEvent.click(screen.getByRole("button", { name: "导入文件" }));
    await screen.findByRole("dialog", { name: "导入加密配置" });
    fireEvent.change(screen.getByLabelText("密码"), {
      target: { value: "wrong" },
    });
    fireEvent.click(screen.getByRole("button", { name: "解密并导入" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("解密失败");
    fireEvent.change(screen.getByLabelText("密码"), {
      target: { value: "right" },
    });
    fireEvent.click(screen.getByRole("button", { name: "解密并导入" }));
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    expect(invoke).toHaveBeenCalledWith("import_profile", {
      path: "/tmp/secret.txt",
      password: "right",
    });
  });
  it("exports an encrypted copy only after the password is confirmed", async () => {
    save.mockResolvedValue("/tmp/out.txt");
    invoke.mockResolvedValue({
      ...structuredClone(initial),
      profiles: [
        {
          id: "a",
          name: "日常",
          source: "本地文件",
          subscription: false,
          encrypted: false,
          pending: false,
          lastChecked: 0,
          lastError: null,
        },
      ],
    });
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "配置" }));
    fireEvent.click(
      await screen.findByRole("button", { name: "加密导出 日常" }),
    );
    fireEvent.change(screen.getByLabelText("密码"), {
      target: { value: "p1" },
    });
    fireEvent.change(screen.getByLabelText("确认密码"), {
      target: { value: "p2" },
    });
    const submit = screen.getByRole("button", { name: "选择位置并导出" });
    expect(submit).toBeDisabled();
    fireEvent.change(screen.getByLabelText("确认密码"), {
      target: { value: "p1" },
    });
    fireEvent.click(submit);
    await waitFor(() =>
      expect(invoke).toHaveBeenCalledWith("export_encrypted", {
        id: "a",
        password: "p1",
        path: "/tmp/out.txt",
      }),
    );
  });
  it("passes the optional subscription password to the backend", async () => {
    invoke.mockImplementation(async (command) => {
      if (command === "add_subscription")
        return { profile: { id: "s", name: "订阅" }, warnings: [] };
      return structuredClone(initial);
    });
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "配置" }));
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "添加订阅" })).toBeEnabled(),
    );
    fireEvent.click(screen.getByRole("button", { name: "添加订阅" }));
    fireEvent.change(screen.getByLabelText("配置名称"), {
      target: { value: "订阅" },
    });
    fireEvent.change(screen.getByLabelText("订阅 URL"), {
      target: { value: "https://example.com/sub" },
    });
    fireEvent.change(screen.getByLabelText("解密密码（可选）"), {
      target: { value: "k" },
    });
    fireEvent.click(screen.getByRole("button", { name: "添加" }));
    await waitFor(() =>
      expect(invoke).toHaveBeenCalledWith("add_subscription", {
        name: "订阅",
        url: "https://example.com/sub",
        password: "k",
      }),
    );
  });
  it("adds custom rules ahead of existing ones and shows skipped reasons", async () => {
    const view = {
      rules: ["DOMAIN,old.test,Gone"],
      targets: ["DIRECT", "REJECT", "Proxy"],
      skipped: [
        {
          rule: "DOMAIN,old.test,Gone",
          reason: "当前配置没有代理或代理组「Gone」",
        },
      ],
      profile: "日常",
    };
    invoke.mockImplementation(async (command, args) => {
      if (command === "custom_rules") return view;
      if (command === "save_custom_rules")
        return { ...view, rules: args.rules, skipped: [] };
      return structuredClone(initial);
    });
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "规则" }));
    expect(await screen.findByText(/当前配置下不生效/)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("规则值"), {
      target: { value: "example.com" },
    });
    fireEvent.change(screen.getByLabelText("目标"), {
      target: { value: "Proxy" },
    });
    fireEvent.click(screen.getByRole("button", { name: "添加" }));
    await waitFor(() =>
      expect(invoke).toHaveBeenCalledWith("save_custom_rules", {
        rules: ["DOMAIN-SUFFIX,example.com,Proxy", "DOMAIN,old.test,Gone"],
      }),
    );
  });
  it("tests routes and DNS leaks on the rules page", async () => {
    const view = {
      rules: ["DOMAIN-SUFFIX,example.com,Proxy"],
      targets: ["DIRECT", "REJECT", "Proxy"],
      skipped: [],
      profile: "日常",
    };
    invoke.mockImplementation(async (command) => {
      if (command === "custom_rules") return view;
      if (command === "test_route")
        return {
          host: "www.example.com",
          port: 443,
          network: "tcp",
          mode: "rule",
          ip: null,
          rule: "DOMAIN-SUFFIX,example.com,Proxy",
          index: 0,
          matched: "DomainSuffix(example.com)",
          chain: ["Proxy", "Auto", "HK 01"],
          node: "HK 01",
          resolved_locally: true,
        };
      if (command === "dns_leak_audit")
        return {
          leaking: true,
          findings: [
            {
              level: "risk",
              code: "resolving-rules",
              title: "1 条 IP 规则会在匹配前本地解析域名",
              detail: "加上 no-resolve",
              items: ["第 3 条：GEOIP,CN,DIRECT"],
            },
          ],
        };
      if (command === "dns_leak_test")
        return {
          exit: [{ ip: "203.0.113.9", country: "Japan", asn: "AS64500" }],
          node: "HK 01",
          matched: "MATCH,Proxy",
          verdict: "ok",
          routed: {
            resolvers: [{ ip: "198.51.100.53", country: "Japan", asn: "" }],
            error: null,
          },
          local: {
            resolvers: [{ ip: "192.0.2.1", country: "China", asn: "" }],
            error: null,
          },
        };
      return { ...structuredClone(initial), status: "running" };
    });
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "规则" }));
    fireEvent.change(await screen.findByLabelText("测试目标"), {
      target: { value: " www.example.com " },
    });
    fireEvent.click(screen.getByRole("button", { name: "测试" }));
    await waitFor(() =>
      expect(invoke).toHaveBeenCalledWith("test_route", {
        target: "www.example.com",
        network: "tcp",
      }),
    );
    expect(await screen.findByText("HK 01")).toBeInTheDocument();
    expect(screen.getByText("Proxy → Auto → HK 01")).toBeInTheDocument();
    expect(screen.getByText(/第 1 条 · 自定义规则/)).toBeInTheDocument();
    expect(screen.getByText(/存在 DNS 泄露/)).toBeInTheDocument();
    expect(screen.getByText("第 3 条：GEOIP,CN,DIRECT")).toBeInTheDocument();
    expect(screen.getByText("配置检查发现 DNS 泄露风险")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "在线检测" }));
    expect(await screen.findByText("198.51.100.53")).toBeInTheDocument();
    expect(screen.getByText("未发现泄露")).toBeInTheDocument();
    expect(screen.getByText("本地解析由这些服务器完成")).toBeInTheDocument();
  });
  it("switches in proxy groups and probes only proxies", async () => {
    const proxy = (name: string) => ({ name, type: "VLESS", history: [] });
    const proxies = {
      Proxy: {
        name: "Proxy",
        type: "Selector",
        all: ["Auto", "DIRECT", "HK 01"],
        now: "Auto",
        history: [],
      },
      Auto: {
        name: "Auto",
        type: "URLTest",
        all: ["HK 01", "JP 01"],
        now: "HK 01",
        history: [],
      },
      DIRECT: { name: "DIRECT", type: "Direct", history: [] },
      "HK 01": proxy("HK 01"),
      "JP 01": proxy("JP 01"),
    };
    invoke.mockImplementation(async (command) => {
      if (command === "proxies") return { proxies };
      if (command === "probe_proxy") return { delay: 88 };
      if (command === "select_proxy") return null;
      return { ...structuredClone(initial), status: "running" };
    });
    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "节点" }));
    const views = within(
      await screen.findByRole("group", { name: "节点视图" }),
    );
    const groupView = views.getByRole("button", { name: /代理组/ });
    if (groupView.getAttribute("aria-pressed") !== "true")
      fireEvent.click(groupView);
    expect(await screen.findAllByText("JP 01")).not.toHaveLength(0);
    expect(screen.queryByRole("button", { name: /延迟/ })).toBeNull();
    expect(screen.queryByRole("button", { name: "测速" })).toBeNull();
    fireEvent.click(screen.getAllByRole("button", { name: /^HK 01/ })[0]);
    await waitFor(() =>
      expect(invoke).toHaveBeenCalledWith("select_proxy", {
        group: "Proxy",
        name: "HK 01",
      }),
    );

    fireEvent.click(views.getByRole("button", { name: /节点/ }));
    expect(
      await screen.findByRole("button", { name: "测试 HK 01 延迟" }),
    ).toBeInTheDocument();
    // Groups and built-in outbounds are not listed with the proxies.
    expect(screen.queryByText("Auto")).toBeNull();
    expect(screen.queryByText("DIRECT")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "测速" }));
    await waitFor(() =>
      expect(invoke).toHaveBeenCalledWith("probe_proxy", { name: "JP 01" }),
    );
    expect(invoke).not.toHaveBeenCalledWith("probe_proxy", { name: "Auto" });
    expect(await screen.findAllByText("88 ms")).toHaveLength(2);
  });
  it("lists recorded requests, shows details and blocks a domain", async () => {
    const entry = {
      id: 1,
      time: Date.now(),
      network: "tcp",
      source: "127.0.0.1:5000",
      host: "ads.example.com",
      port: 443,
      rule: "Match",
      chain: "DIRECT",
      status: "http",
      duration: 120,
      upload: 0,
      download: 10,
      connection: "c1",
      requests: 0,
      http: {
        method: "GET",
        url: "https://ads.example.com/banner.js?id=1",
        decrypted: true,
        status: 200,
        requestSize: 0,
        responseSize: 10,
      },
    };
    const rejected = {
      ...entry,
      id: 2,
      host: "track.example.com",
      status: "rejected",
      rule: "DomainSuffix(example.com)",
      chain: "REJECT",
      http: undefined,
    };
    let served = false;
    invoke.mockImplementation(async (command, args) => {
      if (command === "requests") {
        if (served) return { requests: [], next: 2 };
        served = true;
        expect(args).toEqual({ after: 0 });
        return { requests: [entry, rejected], next: 2 };
      }
      if (command === "request_detail")
        return {
          ...entry,
          requestHeaders: [["Host", "ads.example.com"]],
          responseHeaders: [["Content-Type", "application/json"]],
          requestBody: { size: 0, truncated: false, decoded: false },
          responseBody: {
            size: 10,
            truncated: false,
            decoded: true,
            text: '{"ad":1}',
          },
        };
      if (command === "mitm_info")
        return { ca: null, trusted: false, core: null };
      if (command === "connections")
        return { connections: [], uploadTotal: 0, downloadTotal: 0 };
      if (command === "custom_rules")
        return { rules: ["DOMAIN,old.test,DIRECT"], targets: [], skipped: [] };
      return { ...structuredClone(initial), status: "running" };
    });
    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "抓包" }));
    expect(await screen.findByText("/banner.js?id=1")).toBeInTheDocument();
    expect(screen.getByText("track.example.com")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /已拦截/ }));
    expect(screen.queryByText("/banner.js?id=1")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: /全部/ }));
    save.mockResolvedValue("/tmp/requests.csv");
    fireEvent.click(screen.getByRole("button", { name: "导出" }));
    await waitFor(() =>
      expect(invoke).toHaveBeenCalledWith("export_requests", {
        path: "/tmp/requests.csv",
      }),
    );
    fireEvent.click(screen.getByText("/banner.js?id=1"));
    expect(await screen.findByText(/"ad": 1/)).toBeInTheDocument();
    expect(screen.getByText("https://ads.example.com/banner.js?id=1"));
    fireEvent.click(screen.getByRole("button", { name: "屏蔽此域名" }));
    fireEvent.click(screen.getByLabelText("同时屏蔽它的子域名"));
    fireEvent.click(screen.getByRole("button", { name: "屏蔽" }));
    await waitFor(() =>
      expect(invoke).toHaveBeenCalledWith("save_custom_rules", {
        rules: [
          "DOMAIN-SUFFIX,ads.example.com,REJECT",
          "DOMAIN,old.test,DIRECT",
        ],
      }),
    );
  });
  it("uses core decryption status, structured rewrite actions, and accurate local response labels", async () => {
    const base = {
      time: Date.now(),
      network: "tcp",
      source: "127.0.0.1:5000",
      host: "api.example.com",
      port: 443,
      rule: "Match",
      chain: "DIRECT",
      status: "http",
      duration: 12,
      upload: 0,
      download: 10,
      connection: "c1",
      requests: 0,
    };
    invoke.mockImplementation(async (command) => {
      if (command === "rewrite_status")
        return {
          enabled: true,
          decrypting: true,
          rules: 4,
          rejectRules: 0,
          total: 4,
          rejects: 1,
          rewrites: 3,
          hostnames: ["api.example.com"],
          bypassed: ["pinned.example.com"],
          hits: { "去广告 (测试版)": 4 },
          modules: [
            {
              name: "去广告 (测试版)",
              updateError: "not a rewrite module",
              rules: 4,
              scripts: 0,
              hostnames: 1,
              reject: 0,
              skipped: [],
              missing: [],
            },
          ],
          recent: [],
        };
      if (command === "requests")
        return {
          requests: [
            {
              ...base,
              id: 1,
              http: {
                method: "GET",
                url: "https://api.example.com/feed",
                decrypted: true,
                status: 200,
                requestSize: 0,
                responseSize: 10,
                rewrite: "body (去广告 (测试版))",
                rewriteActions: ["body"],
                answered: false,
              },
            },
            {
              ...base,
              id: 2,
              http: {
                method: "GET",
                url: "https://api.example.com/hdr",
                decrypted: true,
                status: 200,
                requestSize: 0,
                responseSize: 10,
                rewrite: "header (ads, reject list)",
                rewriteActions: ["header"],
                answered: false,
              },
            },
            {
              ...base,
              id: 3,
              http: {
                method: "GET",
                url: "https://api.example.com/redir",
                decrypted: true,
                status: 302,
                requestSize: 0,
                responseSize: 0,
                rewrite: "302 (ads)",
                rewriteActions: ["302"],
                answered: true,
              },
            },
            {
              ...base,
              id: 4,
              http: {
                method: "GET",
                url: "https://api.example.com/ad",
                decrypted: true,
                status: 200,
                requestSize: 0,
                responseSize: 2,
                rewrite: "reject-dict (ads)",
                rewriteActions: ["reject-dict"],
                answered: true,
              },
            },
          ],
          next: 4,
        };
      if (command === "mitm_info")
        return { ca: null, trusted: false, core: null };
      if (command === "connections")
        return { connections: [], uploadTotal: 0, downloadTotal: 0 };
      return { ...structuredClone(initial), status: "running" };
    });
    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "抓包" }));
    expect(await screen.findByText("已加载 1 个模块")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "重试解密" }),
    ).toBeInTheDocument();
    expect(screen.getByText(/证书校验或解密握手失败/)).toBeInTheDocument();
    expect(screen.getByText("已重写 · 正文改写")).toHaveClass("rewrite");
    expect(screen.getByText("已重写 · 请求头改写")).toHaveClass("rewrite");
    expect(screen.getByText("已重写 · 重定向")).toHaveClass("rewrite");
    expect(screen.getByText("已重写 · 拦截 JSON")).toHaveClass("reject");
    expect(screen.getByText("本地响应")).toBeInTheDocument();
    expect(screen.getByText("本地拦截")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "展开模块与记录" }));
    expect(
      screen.getByText("更新失败，仍在使用缓存：not a rewrite module"),
    ).toBeInTheDocument();
  });
  it("formats idle and large transfer counters", () => {
    expect(bytes(0)).toBe("0 B");
    expect(bytes(1024)).toBe("1.0 KB");
    expect(bytes(1024 ** 3)).toBe("1.0 GB");
  });
});

describe("Modal", () => {
  it("keeps focus inside fields when the parent re-renders", () => {
    function Host() {
      const [tick, setTick] = useState(0);
      return (
        <>
          <button onClick={() => setTick((t) => t + 1)}>tick {tick}</button>
          {/* A new onClose on every render, as callers pass inline arrows. */}
          <Modal title="测试" onClose={() => setTick(0)}>
            <input autoFocus aria-label="名称" />
            <select aria-label="格式">
              <option>Clash</option>
              <option>hosts</option>
            </select>
          </Modal>
        </>
      );
    }
    render(<Host />);
    // autoFocus wins over focusing the dialog itself.
    expect(document.activeElement).toBe(screen.getByLabelText("名称"));
    const select = screen.getByLabelText("格式");
    select.focus();
    fireEvent.click(screen.getByText(/^tick/));
    select.focus();
    fireEvent.click(screen.getByText(/^tick/));
    // A re-render must not pull focus back to the dialog (it closed the
    // native select popup).
    act(() => select.focus());
    act(() => {
      screen
        .getByText(/^tick/)
        .dispatchEvent(new MouseEvent("click", { bubbles: true }));
    });
    expect(document.activeElement).not.toBe(screen.getByRole("dialog"));
  });
});

describe("Editor", () => {
  it("marks YAML syntax errors while typing and blocks saving", async () => {
    invoke.mockImplementation(async (command, args) =>
      command === "check_yaml" && args.yaml.includes("[a")
        ? { line: 2, column: 8, message: "方括号列表缺少「,」或「]」" }
        : null,
    );
    const onSave = vi.fn().mockResolvedValue(true);
    render(
      <Editor
        profile={{
          id: "p",
          name: "测试",
          yaml: "mode: rule\n",
          pending: null,
          previous: null,
          url: null,
          mode: "rule",
          lastChecked: 0,
          lastError: null,
        }}
        onClose={vi.fn()}
        onSave={onSave}
      />,
    );
    const editor = screen.getByRole("textbox", { name: "YAML 配置" });
    await waitFor(() =>
      expect(invoke).toHaveBeenCalledWith("check_yaml", {
        yaml: "mode: rule\n",
      }),
    );
    expect(editor).not.toHaveAttribute("aria-invalid");
    fireEvent.change(editor, { target: { value: "mode: rule\nrules: [a\n" } });
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "第 2 行第 8 列：方括号列表缺少「,」或「]」",
    );
    expect(editor).toHaveAttribute("aria-invalid", "true");
    expect(screen.getByRole("button", { name: "保存" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "第 2 行第 8 列" }));
    expect(editor).toHaveFocus();
    expect((editor as HTMLTextAreaElement).selectionStart).toBe(18);

    fireEvent.change(editor, { target: { value: "mode: rule\nrules: []\n" } });
    await waitFor(() => expect(screen.queryByRole("alert")).toBeNull());
    expect(screen.getByRole("button", { name: "保存" })).toBeEnabled();
  });
  it("stops polling while the window is hidden and resumes when shown", async () => {
    vi.useFakeTimers();
    try {
      const handlers: Record<string, (event: { payload: unknown }) => void> =
        {};
      listen.mockImplementation(async (event: string, handler) => {
        handlers[event] = handler;
        return vi.fn();
      });
      invoke.mockImplementation(async (command) =>
        command === "connections"
          ? { connections: [], uploadTotal: 0, downloadTotal: 0 }
          : { ...structuredClone(initial), status: "running" },
      );
      await act(async () => {
        render(<App />);
      });
      const polls = () =>
        invoke.mock.calls.filter(([command]) => command === "connections")
          .length;
      await act(async () => {
        await vi.advanceTimersByTimeAsync(4000);
      });
      expect(polls()).toBeGreaterThanOrEqual(2);
      act(() => handlers["window-visible"]({ payload: false }));
      const hidden = polls();
      await act(async () => {
        await vi.advanceTimersByTimeAsync(20000);
      });
      expect(polls()).toBe(hidden);
      act(() => handlers["window-visible"]({ payload: true }));
      await act(async () => {
        await vi.advanceTimersByTimeAsync(0);
      });
      expect(polls()).toBe(hidden + 1);
    } finally {
      vi.useRealTimers();
    }
  });
  it("opens traffic details from Overview, drills down by host, and closes active connections", async () => {
    let detailsCalls = 0;
    const sampleDetails = {
      since: 1700000000,
      uploadTotal: 256,
      downloadTotal: 1792,
      activeConnections: 1,
      totalConnections: 7,
      totalHosts: 2,
      hostsEvicted: false,
      connectionHost: null,
      matchingActiveConnections: 1,
      matchingClosedConnections: 6,
      retainedClosedConnections: 2,
      hosts: [
        {
          host: "cdn.example.test",
          upload: 128,
          download: 1408,
          activeConnections: 1,
          totalConnections: 6,
          chains: ["ProxyA"],
          rule: "DomainSuffix(example.test)",
          lastSeen: 1700000100,
        },
        {
          host: "small.example.test",
          upload: 28,
          download: 184,
          activeConnections: 0,
          totalConnections: 1,
          chains: ["DIRECT"],
          rule: "Match",
          lastSeen: 1700000050,
        },
      ],
      otherUpload: 100,
      otherDownload: 200,
      otherConnections: 1,
      connections: [
        {
          id: "conn-active",
          host: "cdn.example.test",
          port: 443,
          network: "tcp",
          chains: ["ProxyA"],
          rule: "DomainSuffix(example.test)",
          source: "127.0.0.1",
          upload: 100,
          download: 1024,
          start: 1700000090,
          duration: 5000,
          active: true,
        },
        {
          id: "conn-closed",
          host: "cdn.example.test",
          port: 443,
          network: "tcp",
          chains: ["ProxyA"],
          rule: "DomainSuffix(example.test)",
          source: "127.0.0.1",
          upload: 28,
          download: 384,
          start: 1700000010,
          duration: 1200,
          active: false,
        },
        {
          id: "conn-other",
          host: "small.example.test",
          port: 80,
          network: "tcp",
          chains: ["DIRECT"],
          rule: "Match",
          source: "127.0.0.1",
          upload: 28,
          download: 184,
          start: 1700000005,
          duration: 800,
          active: false,
        },
      ],
    };
    invoke.mockImplementation(async (command, args) => {
      if (command === "connections")
        return { connections: [], uploadTotal: 256, downloadTotal: 1792 };
      if (command === "traffic_details") {
        detailsCalls += 1;
        const host = (args as { host?: string | null } | undefined)?.host ?? null;
        if (host) {
          return {
            ...sampleDetails,
            connectionHost: host,
            matchingActiveConnections: 1,
            matchingClosedConnections: 5,
            retainedClosedConnections: 1,
            connections: sampleDetails.connections.filter(
              (c) => c.host === host,
            ),
          };
        }
        return sampleDetails;
      }
      if (command === "close_connection") return null;
      return { ...structuredClone(initial), status: "running" };
    });

    render(<App />);
    const totalStat = await screen.findByRole("button", { name: /总流量/ });
    await waitFor(() => expect(totalStat).toHaveTextContent("2.0 KB"));
    fireEvent.click(totalStat);

    const dialog = await screen.findByRole("dialog", { name: "流量详情" });
    expect(detailsCalls).toBeGreaterThanOrEqual(1);
    expect(within(dialog).getByText("cdn.example.test")).toBeInTheDocument();
    expect(within(dialog).getByText("75.0%")).toBeInTheDocument();
    expect(within(dialog).getByText("其他目标")).toBeInTheDocument();
    expect(within(dialog).getByText("300 B")).toBeInTheDocument();

    fireEvent.click(within(dialog).getByText("cdn.example.test"));
    await waitFor(() =>
      expect(invoke).toHaveBeenCalledWith("traffic_details", {
        host: "cdn.example.test",
      }),
    );
    expect(
      within(dialog).getByText("目标：cdn.example.test"),
    ).toBeInTheDocument();
    const table = await within(dialog).findByRole("table");
    expect(within(table).getByText("活跃")).toBeInTheDocument();
    expect(within(table).getByText("已结束")).toBeInTheDocument();
    expect(
      within(table).queryByText("small.example.test"),
    ).not.toBeInTheDocument();
    expect(
      within(dialog).getByText("已结束连接仅保留高流量记录，显示 1 / 5 条"),
    ).toBeInTheDocument();

    const beforeClose = detailsCalls;
    fireEvent.click(
      within(dialog).getByRole("button", {
        name: "关闭 cdn.example.test 连接",
      }),
    );
    await waitFor(() =>
      expect(invoke).toHaveBeenCalledWith("close_connection", {
        id: "conn-active",
      }),
    );
    await waitFor(() => expect(detailsCalls).toBeGreaterThan(beforeClose));
  });
  it("serializes traffic details polling and discards stale responses after closing a connection", async () => {
    vi.useFakeTimers();
    try {
      const pending: ((value: unknown) => void)[] = [];
      invoke.mockImplementation((command) => {
        if (command === "connections") {
          return Promise.resolve({
            connections: [],
            uploadTotal: 100,
            downloadTotal: 1000,
          });
        }
        if (command === "traffic_details") {
          return new Promise((resolve) => {
            pending.push(resolve);
          });
        }
        if (command === "close_connection") {
          return Promise.resolve(null);
        }
        return Promise.resolve({ ...structuredClone(initial), status: "running" });
      });

      const activePayload = {
        since: 1700000000,
        uploadTotal: 100,
        downloadTotal: 1000,
        activeConnections: 1,
        totalConnections: 1,
        totalHosts: 1,
        hostsEvicted: false,
        connectionHost: null,
        matchingActiveConnections: 1,
        matchingClosedConnections: 0,
        retainedClosedConnections: 0,
        hosts: [
          {
            host: "cdn.example.test",
            upload: 100,
            download: 1000,
            activeConnections: 1,
            totalConnections: 1,
            chains: ["ProxyA"],
            rule: "Match",
            lastSeen: 1700000010,
          },
        ],
        otherUpload: 0,
        otherDownload: 0,
        otherConnections: 0,
        connections: [
          {
            id: "conn-active",
            host: "cdn.example.test",
            port: 443,
            network: "tcp",
            chains: ["ProxyA"],
            rule: "Match",
            source: "127.0.0.1",
            upload: 100,
            download: 1000,
            start: 1700000010,
            duration: 1000,
            active: true,
          },
        ],
      };

      const closedPayload = {
        ...activePayload,
        activeConnections: 0,
        matchingActiveConnections: 0,
        matchingClosedConnections: 1,
        retainedClosedConnections: 1,
        hosts: [{ ...activePayload.hosts[0], activeConnections: 0 }],
        connections: [{ ...activePayload.connections[0], active: false }],
      };

      await act(async () => {
        render(<App />);
        await vi.advanceTimersByTimeAsync(0);
      });

      const totalStat = screen.getByRole("button", { name: /总流量/ });
      await act(async () => {
        fireEvent.click(totalStat);
        await vi.advanceTimersByTimeAsync(0);
      });

      expect(pending.length).toBe(1);
      // Advancing timers while first poll is still pending must not overlap another poll.
      await act(async () => {
        await vi.advanceTimersByTimeAsync(4000);
      });
      expect(pending.length).toBe(1);

      await act(async () => {
        pending[0](activePayload);
        await vi.advanceTimersByTimeAsync(0);
      });

      const dialog = screen.getByRole("dialog", { name: "流量详情" });
      fireEvent.click(within(dialog).getByRole("button", { name: "按连接" }));
      expect(
        within(within(dialog).getByRole("table")).getByText("活跃"),
      ).toBeInTheDocument();

      // Let next serialized poll start and stay in-flight.
      await act(async () => {
        await vi.advanceTimersByTimeAsync(2000);
      });
      expect(pending.length).toBe(2);

      // Closing triggers a newer refresh while poll #2 is still pending.
      await act(async () => {
        fireEvent.click(
          within(dialog).getByRole("button", {
            name: "关闭 cdn.example.test 连接",
          }),
        );
        await vi.advanceTimersByTimeAsync(0);
      });
      expect(pending.length).toBe(3);

      // Post-close refresh finishes first with closed status.
      await act(async () => {
        pending[2](closedPayload);
        await vi.advanceTimersByTimeAsync(0);
      });
      const table = within(dialog).getByRole("table");
      expect(within(table).getByText("已结束")).toBeInTheDocument();
      expect(within(table).queryByText("活跃")).not.toBeInTheDocument();

      // Earlier pre-close response arrives late: must be ignored.
      await act(async () => {
        pending[1](activePayload);
        await vi.advanceTimersByTimeAsync(0);
      });
      expect(within(table).getByText("已结束")).toBeInTheDocument();
      expect(within(table).queryByText("活跃")).not.toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });
  it("keeps the newly selected host when switching hosts while closing a connection", async () => {
    let resolveClose!: () => void;
    const requestedHosts: (string | null)[] = [];
    const base = {
      since: 1700000000,
      uploadTotal: 200,
      downloadTotal: 2000,
      activeConnections: 2,
      totalConnections: 2,
      totalHosts: 2,
      hostsEvicted: false,
      matchingActiveConnections: 1,
      matchingClosedConnections: 0,
      retainedClosedConnections: 0,
      hosts: [
        {
          host: "alpha.test",
          upload: 100,
          download: 1000,
          activeConnections: 1,
          totalConnections: 1,
          chains: ["ProxyA"],
          rule: "Match",
          lastSeen: 1700000100,
        },
        {
          host: "beta.test",
          upload: 100,
          download: 1000,
          activeConnections: 1,
          totalConnections: 1,
          chains: ["ProxyB"],
          rule: "Match",
          lastSeen: 1700000100,
        },
      ],
      otherUpload: 0,
      otherDownload: 0,
      otherConnections: 0,
    };
    const alphaConn = {
      id: "conn-a",
      host: "alpha.test",
      port: 443,
      network: "tcp",
      chains: ["ProxyA"],
      rule: "Match",
      source: "127.0.0.1",
      upload: 100,
      download: 1000,
      start: 1700000100,
      duration: 1000,
      active: true,
    };
    const betaConn = {
      id: "conn-b",
      host: "beta.test",
      port: 8443,
      network: "tcp",
      chains: ["ProxyB"],
      rule: "Match",
      source: "127.0.0.1",
      upload: 100,
      download: 1000,
      start: 1700000100,
      duration: 1000,
      active: true,
    };

    invoke.mockImplementation(async (command, args) => {
      if (command === "connections")
        return { connections: [], uploadTotal: 200, downloadTotal: 2000 };
      if (command === "traffic_details") {
        const host =
          (args as { host?: string | null } | undefined)?.host ?? null;
        requestedHosts.push(host);
        if (host === "alpha.test") {
          return {
            ...base,
            connectionHost: "alpha.test",
            connections: [alphaConn],
          };
        }
        if (host === "beta.test") {
          return {
            ...base,
            connectionHost: "beta.test",
            connections: [betaConn],
          };
        }
        return {
          ...base,
          connectionHost: null,
          matchingActiveConnections: 2,
          connections: [alphaConn, betaConn],
        };
      }
      if (command === "close_connection") {
        return new Promise<void>((resolve) => {
          resolveClose = resolve;
        });
      }
      return { ...structuredClone(initial), status: "running" };
    });

    render(<App />);
    const totalStat = await screen.findByRole("button", { name: /总流量/ });
    fireEvent.click(totalStat);

    const dialog = await screen.findByRole("dialog", { name: "流量详情" });
    fireEvent.click(await within(dialog).findByText("alpha.test"));
    await within(dialog).findByRole("button", { name: "关闭 alpha.test 连接" });

    // Start closing conn-a, but leave close_connection pending.
    fireEvent.click(
      within(dialog).getByRole("button", { name: "关闭 alpha.test 连接" }),
    );
    await waitFor(() =>
      expect(invoke).toHaveBeenCalledWith("close_connection", { id: "conn-a" }),
    );

    // Switch back to hosts and drill down into beta.test while conn-a close is in flight.
    fireEvent.click(within(dialog).getByRole("button", { name: "按目标" }));
    fireEvent.click(await within(dialog).findByText("beta.test"));
    expect(
      within(dialog).getByText("目标：beta.test"),
    ).toBeInTheDocument();
    await within(dialog).findByRole("button", { name: "关闭 beta.test 连接" });

    const beforeCloseDone = requestedHosts.length;
    await act(async () => {
      resolveClose();
    });

    await waitFor(() =>
      expect(requestedHosts.length).toBeGreaterThan(beforeCloseDone),
    );
    // The post-close refresh must target the currently selected host (beta.test), not alpha.test.
    expect(requestedHosts.slice(beforeCloseDone)).toEqual(["beta.test"]);
    expect(
      within(dialog).getByText("目标：beta.test"),
    ).toBeInTheDocument();
    expect(
      within(dialog).getByRole("button", { name: "关闭 beta.test 连接" }),
    ).toBeInTheDocument();
  });
  it("opens Connections from Overview and sorts rows by total traffic descending", async () => {
    invoke.mockImplementation(async (command) => {
      if (command === "connections") {
        return {
          uploadTotal: 150,
          downloadTotal: 1124,
          connections: [
            {
              id: "light",
              metadata: { host: "light.test", port: 80 },
              network: "tcp",
              chains: ["DIRECT"],
              upload: 50,
              download: 100,
              start: "200",
            },
            {
              id: "heavy",
              metadata: { host: "heavy.test", port: 443 },
              network: "tcp",
              chains: ["ProxyA"],
              upload: 100,
              download: 1024,
              start: "100",
            },
          ],
        };
      }
      return { ...structuredClone(initial), status: "running" };
    });

    render(<App />);
    const connStat = await screen.findByRole("button", { name: /连接数/ });
    fireEvent.click(connStat);

    await screen.findByRole("columnheader", { name: "总计" });
    const rows = screen.getAllByRole("row").slice(1);
    expect(rows[0]).toHaveTextContent("heavy.test");
    expect(rows[0]).toHaveTextContent("1.1 KB");
    expect(rows[1]).toHaveTextContent("light.test");
    expect(rows[1]).toHaveTextContent("150 B");
  });
});
