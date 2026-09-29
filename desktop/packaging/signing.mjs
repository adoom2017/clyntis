import { spawnSync } from "node:child_process";

export const helpers = [
  "clyntis-runner",
  "clyntis-service",
  "clyntis-service-manager",
];

export function selectIdentity(output, env = {}) {
  const identities = Array.from(
    output.matchAll(
      /^\s*\d+\)\s+([A-Fa-f0-9]{40})\s+"(Developer ID Application: .+ \(([A-Z0-9]{10})\))"\s*$/gm,
    ),
    ([, hash, name, team]) => ({ hash, name, team }),
  );
  const requested = env.APPLE_SIGNING_IDENTITY;
  const candidates = identities.filter(
    (identity) =>
      !requested ||
      identity.name === requested ||
      identity.hash.toUpperCase() === requested.toUpperCase(),
  );
  if (candidates.length !== 1) {
    throw new Error(
      candidates.length === 0
        ? "未找到可用的 Developer ID Application 签名身份。请将证书及私钥导入并解锁钥匙串；仅验证普通代理时可使用 npm run desktop:build -- --unsigned。"
        : "存在多个 Developer ID Application 签名身份，请用 APPLE_SIGNING_IDENTITY 指定完整证书名称或 SHA-1 指纹。",
    );
  }
  const identity = candidates[0];
  for (const key of ["CLYNTIS_SIGNING_TEAM_ID", "APPLE_TEAM_ID"]) {
    if (env[key] && env[key] !== identity.team) {
      throw new Error(`${key} 与所选签名证书的 Team ID 不一致`);
    }
  }
  return identity;
}

export function resolveIdentity(env = process.env) {
  const result = spawnSync(
    "/usr/bin/security",
    ["find-identity", "-v", "-p", "codesigning"],
    {
      encoding: "utf8",
      env,
    },
  );
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error("无法读取钥匙串中的代码签名身份");
  return selectIdentity(result.stdout, env);
}

export function signingEnvironment(env, identity) {
  return {
    ...env,
    APPLE_SIGNING_IDENTITY: identity.name,
    CLYNTIS_SIGNING_TEAM_ID: identity.team,
  };
}

export function verifySignature(path, identifier, team) {
  const requirement = `=anchor apple generic and certificate leaf[subject.OU] = "${team}" and identifier "${identifier}"`;
  const verified = spawnSync(
    "/usr/bin/codesign",
    ["--verify", "--strict", "-R", requirement, path],
    { stdio: "inherit" },
  );
  if (verified.error) throw verified.error;
  if (verified.status !== 0) throw new Error(`签名校验失败：${path}`);
  const details = spawnSync(
    "/usr/bin/codesign",
    ["--display", "--verbose=2", path],
    { encoding: "utf8" },
  );
  if (details.error) throw details.error;
  if (
    details.status !== 0 ||
    !/flags=.*\bruntime\b/.test(details.stderr) ||
    !/^Timestamp=/m.test(details.stderr)
  ) {
    throw new Error(`签名缺少 Hardened Runtime 或安全时间戳：${path}`);
  }
}
