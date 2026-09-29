import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "../src/App";
import { bytes, initial } from "../src/types";

const { invoke, listen, open } = vi.hoisted(() => ({
  invoke: vi.fn(),
  listen: vi.fn(),
  open: vi.fn(),
}));
vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/api/event", () => ({ listen }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open, save: vi.fn() }));
beforeEach(() => {
  vi.clearAllMocks();
  listen.mockResolvedValue(vi.fn());
  invoke.mockResolvedValue(structuredClone(initial));
});
afterEach(cleanup);
describe("desktop workflows", () => {
  it("does not connect without a profile and offers an import path", async () => {
    render(<App />);
    await waitFor(() => expect(invoke).toHaveBeenCalledWith("snapshot"));
    expect(screen.getByRole("button", { name: "启动连接" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "添加配置" }));
    expect(screen.getByText("从一个配置开始")).toBeInTheDocument();
  });
  it("imports only after the native file dialog returns a selection", async () => {
    open.mockResolvedValue(null);
    render(<App />);
    await waitFor(() => expect(invoke).toHaveBeenCalledWith("snapshot"));
    fireEvent.click(screen.getByRole("button", { name: "配置管理" }));
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
  it("formats idle and large transfer counters", () => {
    expect(bytes(0)).toBe("0 B");
    expect(bytes(1024)).toBe("1.0 KB");
    expect(bytes(1024 ** 3)).toBe("1.0 GB");
  });
});
