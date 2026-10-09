// @vitest-environment node
import { describe, expect, it } from "vitest";
import { buildVersionArguments } from "../packaging/version.mjs";

describe("desktop build versions", () => {
  it("uses the package version by default and preserves Tauri arguments", () => {
    expect(
      buildVersionArguments(
        ["--unsigned", "--target", "x86_64-apple-darwin"],
        {},
        "1.0.0",
      ),
    ).toEqual({
      args: ["--unsigned", "--target", "x86_64-apple-darwin"],
      version: "1.0.0",
      buildNumber: undefined,
    });
  });
  it("accepts CI environment values and lets CLI arguments override them", () => {
    const env = { CLYNTIS_APP_VERSION: "1.1.0", CLYNTIS_BUILD_NUMBER: "5" };
    expect(buildVersionArguments([], env, "1.0.0")).toMatchObject({
      version: "1.1.0",
      buildNumber: "5",
    });
    expect(
      buildVersionArguments(
        ["--app-version", "1.2.3", "--build-number", "17", "--bundles", "app"],
        env,
        "1.0.0",
      ),
    ).toEqual({
      args: ["--bundles", "app"],
      version: "1.2.3",
      buildNumber: "17",
    });
  });
  it("treats empty environment values as unset", () => {
    const env = { CLYNTIS_APP_VERSION: "", CLYNTIS_BUILD_NUMBER: "" };
    expect(buildVersionArguments([], env, "1.0.0")).toMatchObject({
      version: "1.0.0",
      buildNumber: undefined,
    });
  });
  it("ignores the shared environment build number outside macOS", () => {
    const env = { CLYNTIS_APP_VERSION: "1.1.0", CLYNTIS_BUILD_NUMBER: "5" };
    expect(buildVersionArguments([], env, "1.0.0", false)).toMatchObject({
      version: "1.1.0",
      buildNumber: undefined,
    });
    expect(() =>
      buildVersionArguments(["--build-number", "5"], {}, "1.0.0", false),
    ).toThrow();
  });
  it("rejects incomplete and invalid metadata before invoking the compiler", () => {
    for (const args of [
      ["--app-version"],
      ["--build-number", "--unsigned"],
      ["--app-version", "v1.0.0"],
      ["--app-version", "1.0.0-beta"],
      ["--app-version", "01.0.0"],
      ["--build-number", "0"],
      ["--build-number", "17\nOTHER=1"],
    ])
      expect(() => buildVersionArguments(args, {}, "1.0.0")).toThrow();
  });
});
