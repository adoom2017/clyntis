import { spawnSync } from "node:child_process";
import {
  mkdirSync,
  copyFileSync,
  readFileSync,
  writeFileSync,
  existsSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import {
  helpers,
  resolveIdentity,
  signingEnvironment,
  verifySignature,
} from "./signing.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const debug = process.argv.includes("--debug");
function run(command, args, extra = {}) {
  const result = spawnSync(command, args, {
    cwd: root,
    stdio: "inherit",
    ...extra,
  });
  if (result.error) throw result.error;
  if (result.status !== 0)
    throw new Error(`${command} exited with ${result.status}`);
  return result;
}
const host = spawnSync("rustc", ["-vV"], { encoding: "utf8" }).stdout.match(
  /^host: (.+)$/m,
)[1];
const target = process.env.CLYNTIS_DESKTOP_TARGET || host;
const explicitTarget = !!process.env.CLYNTIS_DESKTOP_TARGET;
let env = { ...process.env, MACOSX_DEPLOYMENT_TARGET: "13.0" };
let identity;
if (target.includes("apple") && env.APPLE_SIGNING_IDENTITY) {
  identity = resolveIdentity(env);
  env = signingEnvironment(env, identity);
}
if (
  ![
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "x86_64-pc-windows-msvc",
  ].includes(target)
)
  throw new Error(`Unsupported desktop target: ${target}`);
const args = [
  "build",
  "--locked",
  "-p",
  "clyntis-desktop-runner",
  "-p",
  "clyntis-desktop-service",
];
if (!debug) args.push("--release");
if (explicitTarget) args.push("--target", target);
run("cargo", args, {
  env: {
    ...env,
    CLYNTIS_SIGNING_TEAM_ID:
      env.CLYNTIS_SIGNING_TEAM_ID || env.APPLE_TEAM_ID || "",
  },
});
const bin = join(root, "src-tauri", "binaries");
mkdirSync(bin, { recursive: true });
const build = join(
  resolve(root, env.CARGO_TARGET_DIR || "target"),
  ...(explicitTarget ? [target] : []),
  debug ? "debug" : "release",
);
const extension = target.includes("windows") ? ".exe" : "";
for (const name of ["clyntis-runner", "clyntis-service"])
  copyFileSync(
    join(build, name + extension),
    join(bin, `${name}-${target}${extension}`),
  );
if (target.includes("apple")) {
  const swiftTarget = `${target.startsWith("aarch64") ? "arm64" : "x86_64"}-apple-macos13.0`;
  run("xcrun", [
    "swiftc",
    "-parse-as-library",
    "-O",
    "-target",
    swiftTarget,
    "-module-cache-path",
    join(root, "target", "swift-cache"),
    "packaging/macos/ServiceManager.swift",
    "-o",
    join(build, "clyntis-service-manager"),
  ]);
  copyFileSync(
    join(build, "clyntis-service-manager"),
    join(bin, `clyntis-service-manager-${target}`),
  );
  if (identity) {
    // Rust's linker creates hashed ad-hoc identifiers. Pin the production
    // identifiers before Tauri signs the nested bundle so the service can
    // verify the exact roles of its immutable helper copies.
    for (const name of helpers) {
      run("/usr/bin/codesign", [
        "--force",
        "--sign",
        identity.hash,
        "--identifier",
        name,
        "--options",
        "runtime",
        "--timestamp",
        join(bin, `${name}-${target}`),
      ]);
      verifySignature(join(bin, `${name}-${target}`), name, identity.team);
    }
  }
}
if (target.includes("windows")) {
  const archive = join(bin, "wintun-0.14.1.zip");
  // Official WireGuard distribution; pin the archive, not just the DLL name.
  const expected =
    "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51";
  if (!existsSync(archive)) {
    const response = await fetch(
      "https://www.wintun.net/builds/wintun-0.14.1.zip",
    );
    if (!response.ok) throw new Error(`Wintun download: ${response.status}`);
    writeFileSync(archive, Buffer.from(await response.arrayBuffer()));
  }
  if (
    createHash("sha256").update(readFileSync(archive)).digest("hex") !==
    expected
  )
    throw new Error("Wintun archive checksum mismatch");
  const script =
    "Expand-Archive -LiteralPath $env:CLYNTIS_WINTUN_ARCHIVE -DestinationPath $env:CLYNTIS_WINTUN_DEST -Force";
  run("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], {
    env: {
      ...process.env,
      CLYNTIS_WINTUN_ARCHIVE: archive,
      CLYNTIS_WINTUN_DEST: bin,
    },
  });
  copyFileSync(
    join(bin, "wintun", "bin", "amd64", "wintun.dll"),
    join(bin, "wintun.dll"),
  );
  copyFileSync(
    join(bin, "wintun", "LICENSE.txt"),
    join(bin, "wintun-LICENSE.txt"),
  );
  copyFileSync(join(bin, "wintun.dll"), join(build, "wintun.dll"));
}
console.log(`Desktop sidecars ready: ${target}`);
