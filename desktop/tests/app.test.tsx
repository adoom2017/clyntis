import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App, { Modal } from "../src/App";
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
  it("tests which rule and node a domain would use", async () => {
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
