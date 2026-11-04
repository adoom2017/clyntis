import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { UpdatesPanel, useUpdates, type UpdateState } from "../src/Updates";
import { setLanguage } from "../src/i18n";
import App from "../src/App";
import { initial } from "../src/types";

const { invoke, listen } = vi.hoisted(() => ({
  invoke: vi.fn(),
  listen: vi.fn(),
}));
vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/api/event", () => ({ listen }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn(), save: vi.fn() }));
let push: (payload: UpdateState) => void;
const available: UpdateState = {
  phase: "available",
  version: "1.3.0",
  notes: "<script>alert(1)</script>",
  error: null,
  downloaded: 0,
  total: null,
  checkedAt: 12345,
};
function Harness({ install = vi.fn(), busy = false }) {
  const updates = useUpdates();
  return <UpdatesPanel updates={updates} busy={busy} onInstall={install} />;
}
beforeEach(() => {
  vi.clearAllMocks();
  setLanguage("zh");
  invoke.mockImplementation((command) =>
    Promise.resolve(command === "app_update_state" ? available : undefined),
  );
  listen.mockImplementation(async (event, callback) => {
    if (event === "app-update") push = (payload) => callback({ payload });
    return vi.fn();
  });
});
afterEach(cleanup);

describe("desktop updates", () => {
  it("does not overwrite a live event with an older initial snapshot", async () => {
    let resolve!: (state: UpdateState) => void;
    invoke.mockReturnValue(
      new Promise<UpdateState>((r) => {
        resolve = r;
      }),
    );
    render(<Harness />);
    await waitFor(() =>
      expect(invoke).toHaveBeenCalledWith("app_update_state"),
    );
    act(() => push({ ...available, phase: "ready" }));
    await act(async () => resolve({ ...available, phase: "idle" }));
    expect(screen.getByRole("button", { name: "安装并重启" })).toBeEnabled();
  });

  it("downloads without installing and waits for verification before offering installation", async () => {
    const install = vi.fn();
    render(<Harness install={install} />);
    const download = await screen.findByRole("button", { name: "下载更新" });
    fireEvent.click(download);
    await waitFor(() =>
      expect(invoke).toHaveBeenCalledWith("download_app_update"),
    );
    expect(invoke).not.toHaveBeenCalledWith("install_app_update");
    act(() =>
      push({
        ...available,
        phase: "downloading",
        downloaded: 512,
        total: 1024,
      }),
    );
    expect(screen.getByRole("progressbar")).toHaveAttribute("value", "512");
    expect(
      screen.queryByRole("button", { name: "安装并重启" }),
    ).not.toBeInTheDocument();
    act(() => push({ ...available, phase: "ready" }));
    fireEvent.click(screen.getByRole("button", { name: "安装并重启" }));
    expect(install).toHaveBeenCalledOnce();
    // Release notes remain plain text even if the release contains HTML.
    expect(document.querySelector(".update-notes script")).toBeNull();
  });

  it("shows verification failures, permits retry, and never offers install", async () => {
    invoke.mockImplementation((command) =>
      command === "app_update_state"
        ? Promise.resolve(available)
        : Promise.reject("Signature mismatch"),
    );
    render(<Harness />);
    fireEvent.click(await screen.findByRole("button", { name: "下载更新" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Signature mismatch",
    );
    expect(screen.getByRole("button", { name: "下载更新" })).toBeEnabled();
    expect(
      screen.queryByRole("button", { name: "安装并重启" }),
    ).not.toBeInTheDocument();
    act(() => push(available));
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("disables update actions for unsigned builds and unsaved settings", async () => {
    const { rerender } = render(<Harness busy />);
    expect(
      await screen.findByRole("button", { name: "下载更新" }),
    ).toBeDisabled();
    rerender(<Harness />);
    act(() => push({ ...available, phase: "disabled", version: null }));
    expect(
      screen.getByRole("button", { name: "检查客户端更新" }),
    ).toBeDisabled();
    expect(screen.getByRole("status")).toHaveTextContent("未配置更新签名");
  });

  it("blocks duplicate requests while one is outstanding", async () => {
    render(<Harness />);
    const download = await screen.findByRole("button", { name: "下载更新" });
    invoke.mockReturnValue(new Promise(() => {}));
    fireEvent.click(download);
    fireEvent.click(download);
    expect(
      invoke.mock.calls.filter(
        ([command]) => command === "download_app_update",
      ),
    ).toHaveLength(1);
    expect(download).toBeDisabled();
  });

  it("requires explicit confirmation before stopping connections and installing", async () => {
    const snapshot = structuredClone(initial);
    snapshot.settings.language = "zh";
    invoke.mockImplementation((command) =>
      Promise.resolve(
        command === "snapshot"
          ? snapshot
          : command === "app_update_state"
            ? { ...available, phase: "ready" }
            : undefined,
      ),
    );
    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "设置" }));
    fireEvent.click(await screen.findByRole("button", { name: "安装并重启" }));
    expect(screen.getByRole("dialog")).toHaveTextContent(
      "正在进行的连接会中断",
    );
    expect(invoke).not.toHaveBeenCalledWith("install_app_update");
    fireEvent.click(screen.getByRole("button", { name: "取消" }));
    expect(invoke).not.toHaveBeenCalledWith("install_app_update");
    fireEvent.click(screen.getByRole("button", { name: "安装并重启" }));
    fireEvent.click(screen.getByRole("button", { name: "确认" }));
    await waitFor(() =>
      expect(invoke).toHaveBeenCalledWith("install_app_update"),
    );
  });
});
