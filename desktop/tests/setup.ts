import "@testing-library/jest-dom/vitest";

// jsdom reports en-US; the existing tests read the Chinese interface, which
// "follow the system" picks on a Chinese system. Node-environment tests
// have no window.
if (typeof window !== "undefined")
  Object.defineProperty(window.navigator, "languages", {
    configurable: true,
    get: () => ["zh-CN"],
  });
