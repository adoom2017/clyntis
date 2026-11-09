import { useSyncExternalStore } from "react";
import { listen } from "@tauri-apps/api/event";

/** Whether the window is shown, as the backend reports when it hides the
 * window to the tray: WebKit and WebView2 do not always mark a hidden
 * window's page as hidden. */
let windowShown = true;
const subscribers = new Set<() => void>();
/** Removes the backend listener; set while anyone subscribes. */
let unlisten: Promise<(() => void) | undefined> | null = null;

const notify = () => subscribers.forEach((update) => update());

function register() {
  document.addEventListener("visibilitychange", notify);
  unlisten = Promise.resolve(
    listen<boolean>("window-visible", ({ payload }) => {
      windowShown = payload;
      notify();
    }),
  ).catch(() => undefined);
}

function unregister() {
  document.removeEventListener("visibilitychange", notify);
  void unlisten?.then((off) => off?.());
  unlisten = null;
}

/** Whether anyone can see the page: the window is shown and not minimized
 * or covered (the page's visibility). */
export const pageVisible = () =>
  windowShown && document.visibilityState !== "hidden";

const subscribe = (update: () => void) => {
  if (subscribers.size === 0) register();
  subscribers.add(update);
  return () => {
    subscribers.delete(update);
    if (subscribers.size === 0) unregister();
  };
};

/** Re-renders when the page is shown or hidden. Polling stops while hidden:
 * nobody reads the numbers, and each poll woke the core, the app and WebKit. */
export const usePageVisible = () =>
  useSyncExternalStore(subscribe, pageVisible, () => true);
