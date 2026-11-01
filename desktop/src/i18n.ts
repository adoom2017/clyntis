import { en } from "./locales/en";

/** The setting: follow the system, or a fixed language. */
export type Language = "system" | "zh" | "en";
/** The language in effect. */
export type Resolved = "zh" | "en";

let current: Resolved = "zh";

/** The first of the system's preferred languages we have; English otherwise. */
export function systemLanguage(): Resolved {
  const preferred = navigator.languages?.length
    ? navigator.languages
    : [navigator.language];
  for (const tag of preferred) {
    const lower = tag.toLowerCase();
    if (lower.startsWith("zh")) return "zh";
    if (lower.startsWith("en")) return "en";
  }
  return "en";
}

export function resolveLanguage(setting: Language | undefined): Resolved {
  return setting === "zh" || setting === "en" ? setting : systemLanguage();
}

export function setLanguage(language: Resolved) {
  current = language;
  document.documentElement.lang = language === "zh" ? "zh-CN" : "en";
}

export function language(): Resolved {
  return current;
}

/** For dates and numbers in the interface language. */
export function locale() {
  return current === "zh" ? "zh-CN" : "en-US";
}

/**
 * The interface text for `text`, written in Chinese: its English entry when
 * English is in effect. `{name}` placeholders take `params`.
 */
export function t(text: string, params?: Record<string, string | number>) {
  const template = current === "en" ? (en[text] ?? text) : text;
  if (!params) return template;
  return template.replace(/\{(\w+)\}/g, (match: string, key: string) =>
    key in params ? String(params[key]) : match,
  );
}

/**
 * `t` for a word whose English depends on where it appears: looks up
 * `context|text` first ("mode|规则" is "Rule", the page "规则" is "Rules").
 */
export function tx(
  context: string,
  text: string,
  params?: Record<string, string | number>,
) {
  if (current === "en" && en[`${context}|${text}`] !== undefined)
    return t(`${context}|${text}`, params);
  return t(text, params);
}
