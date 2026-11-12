import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "../src/App";
import { en } from "../src/locales/en";
import { initial } from "../src/types";

const { invoke, listen } = vi.hoisted(() => ({
  invoke: vi.fn(),
  listen: vi.fn(),
}));
vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/api/event", () => ({ listen }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn(), save: vi.fn() }));

const system = (languages: string[]) =>
  Object.defineProperty(window.navigator, "languages", {
    configurable: true,
    get: () => languages,
  });
const withLanguage = (language: "system" | "zh" | "en") => {
  const state = structuredClone(initial);
  state.settings.language = language;
  invoke.mockResolvedValue(state);
};
const placeholders = (text: string) =>
  [...text.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();

beforeEach(() => {
  vi.clearAllMocks();
  listen.mockResolvedValue(vi.fn());
});
afterEach(() => {
  cleanup();
  system(["zh-CN"]);
});

describe("interface language", () => {
  it("has English for every text in the source, with the same placeholders", () => {
    const src = join(process.cwd(), "src");
    const files = readdirSync(src, { recursive: true, encoding: "utf8" })
      .map((file) => file.replaceAll("\\", "/"))
      .filter((file) => /\.tsx?$/.test(file))
      .filter((file) => !file.startsWith("locales"));
    // The pages and sections live in their own files now.
    expect(files).toContain("pages/Settings.tsx");
    const source = files
      .map((file) => readFileSync(join(src, file), "utf8"))
      .join("\n");
    const keys = new Set<string>();
    for (const m of source.matchAll(/\bt\(\s*"((?:[^"\\]|\\.)*)"/g))
      keys.add(m[1]);
    for (const m of source.matchAll(
      /\btx\(\s*"(\w+)",\s*"((?:[^"\\]|\\.)*)"/g,
    )) {
      keys.add(m[2]);
      keys.add(`${m[1]}|${m[2]}`);
    }
    expect(keys.size).toBeGreaterThan(300);
    const missing = [...keys].filter((key) => en[key] === undefined);
    expect(missing).toEqual([]);
    for (const [key, value] of Object.entries(en))
      expect(placeholders(value), key).toEqual(
        placeholders(key.split("|").at(-1)!),
      );
    // Nothing stale: every entry is still used.
    expect(Object.keys(en).filter((key) => !keys.has(key))).toEqual([]);
  });

  it("follows an English system and tells the backend", async () => {
    system(["en-US"]);
    withLanguage("system");
    render(<App />);
    expect(
      await screen.findByRole("button", { name: "Overview" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Settings" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Not connected", { selector: "h2" })).toBeVisible();
    await waitFor(() =>
      expect(invoke).toHaveBeenCalledWith("set_language", { language: "en" }),
    );
    expect(document.documentElement.lang).toBe("en");
  });

  it("falls back to English for a system language without a translation", async () => {
    system(["ja-JP"]);
    withLanguage("system");
    render(<App />);
    expect(
      await screen.findByRole("button", { name: "Overview" }),
    ).toBeInTheDocument();
  });

  it("keeps a chosen language whatever the system uses", async () => {
    system(["en-US"]);
    withLanguage("zh");
    render(<App />);
    await waitFor(() =>
      expect(invoke).toHaveBeenCalledWith("set_language", { language: "zh" }),
    );
    expect(screen.getByRole("button", { name: "概览" })).toBeInTheDocument();
    expect(document.documentElement.lang).toBe("zh-CN");
  });
});
