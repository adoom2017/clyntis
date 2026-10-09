// Command-line flags win over environment values; empty values count as unset.
// The environment build number is shared with iOS, so it is dropped (not an
// error) when the bundle has no macOS build number.
export function buildVersionArguments(input, env, defaultVersion, mac = true) {
  const args = [];
  let version = env.CLYNTIS_APP_VERSION || defaultVersion;
  let buildNumber = mac ? env.CLYNTIS_BUILD_NUMBER || undefined : undefined;
  for (let i = 0; i < input.length; i++) {
    const flag = input[i];
    if (flag !== "--app-version" && flag !== "--build-number") {
      args.push(flag);
      continue;
    }
    const value = input[++i];
    if (!value || value.startsWith("-")) throw new Error(`${flag} 需要一个值`);
    if (flag === "--app-version") version = value;
    else if (mac) buildNumber = value;
    else throw new Error("--build-number 仅适用于 macOS 应用包");
  }
  if (!/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(version))
    throw new Error("应用版本号必须为 X.Y.Z，例如 1.2.3");
  if (buildNumber !== undefined && !/^[1-9]\d*$/.test(buildNumber))
    throw new Error("构建号必须为正整数，例如 17");
  return { args, version, buildNumber };
}
