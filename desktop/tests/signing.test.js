// @vitest-environment node
import { describe, expect, it } from "vitest";
import { selectIdentity, signingEnvironment } from "../packaging/signing.mjs";

const hash = "A".repeat(40);
const name = "Developer ID Application: Example Developer (ABCDEFGHIJ)";
const identities = `
  1) ${"B".repeat(40)} "Apple Development: Example (0123456789)"
  2) ${hash} "${name}"
  3) ${"C".repeat(40)} "3rd Party Mac Developer Application: Example (ABCDEFGHIJ)"
     3 valid identities found
`;

describe("macOS signing selection", () => {
  it("selects only Developer ID Application identities and derives the service team", () => {
    const identity = selectIdentity(identities);
    expect(identity).toEqual({ hash, name, team: "ABCDEFGHIJ" });
    expect(signingEnvironment({ PATH: "/bin" }, identity)).toEqual({
      PATH: "/bin",
      APPLE_SIGNING_IDENTITY: name,
      CLYNTIS_SIGNING_TEAM_ID: "ABCDEFGHIJ",
    });
  });
  it("accepts an explicit certificate name or fingerprint", () => {
    for (const requested of [name, hash.toLowerCase()]) {
      expect(
        selectIdentity(identities, { APPLE_SIGNING_IDENTITY: requested }).team,
      ).toBe("ABCDEFGHIJ");
    }
  });
  it("fails before building when the keychain identity is missing or ambiguous", () => {
    expect(() => selectIdentity("0 valid identities found")).toThrow("未找到");
    expect(() =>
      selectIdentity(identities, { APPLE_SIGNING_IDENTITY: "-" }),
    ).toThrow("未找到");
    const multiple = `${identities}\n  4) ${"D".repeat(40)} "Developer ID Application: Other (1234567890)"`;
    expect(() => selectIdentity(multiple)).toThrow("多个");
    expect(
      selectIdentity(multiple, { APPLE_SIGNING_IDENTITY: name }).name,
    ).toBe(name);
  });
  it("rejects a service or notarization team that differs from the certificate", () => {
    for (const key of ["CLYNTIS_SIGNING_TEAM_ID", "APPLE_TEAM_ID"]) {
      expect(() => selectIdentity(identities, { [key]: "OTHERTEAM1" })).toThrow(
        "不一致",
      );
    }
  });
});
