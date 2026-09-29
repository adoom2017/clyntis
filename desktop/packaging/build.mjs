import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";
import {
  helpers,
  resolveIdentity,
  signingEnvironment,
  verifySignature,
} from "./signing.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const input = process.argv.slice(2);
const unsigned = input.includes("--unsigned") || input.includes("--no-sign");
const args = input.filter((arg) => !["--unsigned", "--no-sign"].includes(arg));
const targetIndex = args.findIndex((arg) => arg === "--target" || arg === "-t");
const target =
  targetIndex < 0 ? process.env.CLYNTIS_DESKTOP_TARGET : args[targetIndex + 1];
if (targetIndex >= 0 && (!target || target.startsWith("-")))
  throw new Error("--target 需要目标架构");
if (targetIndex < 0 && target) args.push("--target", target);
const mac =
  process.platform === "darwin" && (!target || target.includes("apple-darwin"));
let env = { ...process.env };
if (target) env.CLYNTIS_DESKTOP_TARGET = target;
if (mac) env.MACOSX_DEPLOYMENT_TARGET = "13.0";
let identity;
if (mac && !unsigned) {
  if (args.includes("--no-bundle"))
    throw new Error("签名打包需要生成应用包，请移除 --no-bundle");
  identity = resolveIdentity(env);
  env = signingEnvironment(env, identity);
  console.log(`签名身份：${identity.name}\n辅助服务 Team ID：${identity.team}`);
} else if (mac) {
  for (const key of [
    "APPLE_SIGNING_IDENTITY",
    "APPLE_CERTIFICATE",
    "APPLE_CERTIFICATE_PASSWORD",
    "APPLE_TEAM_ID",
    "CLYNTIS_SIGNING_TEAM_ID",
  ])
    delete env[key];
  console.log("构建未签名验证包：仅支持手动代理，辅助服务不可用。");
}
if (unsigned) args.push("--no-sign");
function run(command, args) {
  const result = spawnSync(command, args, { cwd: root, env, stdio: "inherit" });
  if (result.error) throw result.error;
  if (result.status !== 0)
    throw new Error(`${command} exited with ${result.status}`);
}
run(process.execPath, [
  "packaging/prepare.mjs",
  ...(args.includes("--debug") || args.includes("-d") ? ["--debug"] : []),
]);
run(process.execPath, [
  "node_modules/@tauri-apps/cli/tauri.js",
  "build",
  ...args,
]);
if (identity) {
  const config = JSON.parse(
    readFileSync(join(root, "src-tauri/tauri.conf.json"), "utf8"),
  );
  const app = join(
    resolve(root, env.CARGO_TARGET_DIR || "target"),
    ...(target ? [target] : []),
    args.includes("--debug") || args.includes("-d") ? "debug" : "release",
    "bundle/macos",
    `${config.productName}.app`,
  );
  for (const name of helpers)
    verifySignature(join(app, "Contents/MacOS", name), name, identity.team);
  verifySignature(app, config.identifier, identity.team);
  console.log(`签名校验通过：主应用及全部辅助程序使用同一 Team ID。\n${app}`);
}
