// @vitest-environment node
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  collectUpdates,
  createManifest,
  updateFilename,
  updatePlatforms,
  updaterBuildConfig,
  validateSignatureMetadata,
} from "../packaging/updates.mjs";

const directories = [];
const signatureFor = (version) =>
  Buffer.from(
    `untrusted comment: test\nplaceholder\ntrusted comment: timestamp:0\tfile:fixture\tversion:${version}\nplaceholder`,
  ).toString("base64");
function temporary() {
  const directory = mkdtempSync(join(tmpdir(), "clyntis-updates-test-"));
  directories.push(directory);
  return directory;
}
afterEach(() => {
  for (const dir of directories.splice(0)) {
    if (
      dirname(resolve(dir)) !== resolve(tmpdir()) ||
      !basename(dir).startsWith("clyntis-updates-test-")
    )
      throw new Error("Refusing to remove an unexpected test directory");
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("update release packaging", () => {
  it("keeps validation builds usable without signing keys", () => {
    expect(
      updaterBuildConfig(false, {}, true, true).bundle.createUpdaterArtifacts,
    ).toBe(false);
    expect(() => updaterBuildConfig(true, {}, false, false)).toThrow(
      "TAURI_SIGNING_PRIVATE_KEY",
    );
    expect(() => updaterBuildConfig(true, {}, true, true)).toThrow(
      "Developer ID",
    );
    expect(() => updaterBuildConfig(true, {}, false, true)).toThrow(
      "skips updater signatures",
    );
  });

  it("requires an actual public key and HTTPS endpoint", () => {
    const env = {
      TAURI_SIGNING_PRIVATE_KEY: "secret",
      CLYNTIS_UPDATER_PUBLIC_KEY: "placeholder",
    };
    expect(() => updaterBuildConfig(true, env, false, false)).toThrow(
      "public key",
    );
    env.CLYNTIS_UPDATER_PUBLIC_KEY = Buffer.from(
      "untrusted comment: test\n" +
        Buffer.concat([Buffer.from("Ed"), Buffer.alloc(40)]).toString("base64"),
    ).toString("base64");
    expect(
      updaterBuildConfig(true, env, false, false).bundle.createUpdaterArtifacts,
    ).toBe(true);
    env.CLYNTIS_UPDATER_ENDPOINT = "http://example.com/latest.json";
    expect(() => updaterBuildConfig(true, env, false, false)).toThrow("HTTPS");
  });

  it("collects architecture-specific macOS packages without filename collisions", () => {
    const directory = temporary();
    const bundle = join(directory, "bundle");
    const output = join(directory, "assets");
    mkdirSync(bundle);
    writeFileSync(join(bundle, "Clyntis.app.tar.gz"), "signed app");
    expect(() =>
      collectUpdates(bundle, output, "darwin-aarch64", "1.3.0"),
    ).toThrow();
    const signature = signatureFor("1.3.0");
    writeFileSync(join(bundle, "Clyntis.app.tar.gz.sig"), signature);
    collectUpdates(bundle, output, "darwin-aarch64", "1.3.0");
    collectUpdates(bundle, output, "darwin-x86_64", "1.3.0");
    for (const platform of ["darwin-aarch64", "darwin-x86_64"]) {
      const name = updateFilename(platform, "1.3.0");
      expect(readFileSync(join(output, name), "utf8")).toBe("signed app");
      expect(readFileSync(join(output, `${name}.sig`), "utf8")).toBe(
        signature + "\n",
      );
    }
  });

  it("refuses partial releases and writes all three platform URLs and signatures", () => {
    const directory = temporary();
    expect(() =>
      createManifest(directory, "1.3.0", "adoom2017/clyntis"),
    ).toThrow();
    for (const platform of Object.keys(updatePlatforms)) {
      const name = updateFilename(platform, "1.3.0");
      writeFileSync(join(directory, name), "installer");
      writeFileSync(join(directory, `${name}.sig`), signatureFor("1.3.0"));
    }
    const result = createManifest(
      directory,
      "1.3.0",
      "adoom2017/clyntis",
      "Release notes",
      new Date("2026-11-04T00:00:00Z"),
    );
    expect(Object.keys(result.platforms)).toHaveLength(3);
    expect(result.pub_date).toBe("2026-11-04T00:00:00.000Z");
    expect(result.platforms["windows-x86_64"]).toEqual({
      signature: signatureFor("1.3.0"),
      url: "https://github.com/adoom2017/clyntis/releases/download/v1.3.0/Clyntis_1.3.0_x64-setup.exe",
    });
    expect(() =>
      createManifest(directory, "../1.3.0", "adoom2017/clyntis"),
    ).toThrow();
    expect(() => createManifest(directory, "1.3.0", "../../other")).toThrow();
  });

  it("rejects legacy signatures and signatures for a different app version", () => {
    expect(() => validateSignatureMetadata("signature", "1.3.0")).toThrow(
      "signature version",
    );
    expect(() =>
      validateSignatureMetadata(signatureFor("1.2.0"), "1.3.0"),
    ).toThrow("signature version");
    expect(() =>
      validateSignatureMetadata(signatureFor("1.3.0"), "1.3.0"),
    ).not.toThrow();
  });
});
