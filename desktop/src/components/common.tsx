import { useEffect, useRef, type ReactNode } from "react";
import { X } from "lucide-react";
import { t } from "../i18n";

export type Perform = (
  action: () => Promise<unknown>,
  success?: string,
) => Promise<boolean>;
export function Stat({
  label,
  value,
  icon,
  tone = "neutral",
}: {
  label: string;
  value: string;
  icon: ReactNode;
  tone?: string;
}) {
  return (
    <section className="panel stat">
      <span>
        <span className={`stat-icon ${tone}`}>{icon}</span>
        {label}
      </span>
      <strong>{value}</strong>
    </section>
  );
}
export function Empty({
  icon,
  title,
  text,
  children,
}: {
  icon: ReactNode;
  title: string;
  text?: string;
  children?: ReactNode;
}) {
  return (
    <section className="panel empty">
      <span className="empty-icon">{icon}</span>
      <h2>{title}</h2>
      {text && <p>{text}</p>}
      {children}
    </section>
  );
}
export function Modal({
  title,
  onClose,
  children,
  wide = false,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  wide?: boolean;
}) {
  const ref = useRef<HTMLDivElement>(null);
  // Callers pass a new onClose on every render; reading it through a ref keeps
  // the effect below to mount and unmount. Re-running it on each parent render
  // moved focus back to the dialog, closing an open <select> and interrupting
  // typing.
  const close = useRef(onClose);
  close.current = onClose;
  useEffect(() => {
    const previous = document.activeElement as HTMLElement;
    // Leave focus on an autoFocus field inside the dialog.
    if (!ref.current?.contains(document.activeElement)) ref.current?.focus();
    const handler = (event: KeyboardEvent) => {
      if (event.key === "Escape") close.current();
      if (event.key === "Tab") {
        const items = ref.current?.querySelectorAll<HTMLElement>(
          'button:not(:disabled),input,textarea,select,[tabindex="0"]',
        );
        if (!items?.length) return;
        const first = items[0],
          last = items[items.length - 1];
        if (
          event.shiftKey &&
          (document.activeElement === first ||
            document.activeElement === ref.current)
        ) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener("keydown", handler);
    return () => {
      document.removeEventListener("keydown", handler);
      previous?.focus();
    };
  }, []);
  return (
    <div className="modal-backdrop">
      <div
        className={`modal ${wide ? "wide" : ""}`}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        tabIndex={-1}
        ref={ref}
      >
        <div className="modal-heading">
          <h2>{title}</h2>
          <button
            className="icon-button"
            aria-label={t("关闭")}
            onClick={onClose}
          >
            <X size={18} />
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}
export function Confirm({
  title,
  text,
  danger,
  onClose,
  onConfirm,
}: {
  title: string;
  text: string;
  danger?: boolean;
  onClose: () => void;
  onConfirm: () => Promise<void>;
}) {
  return (
    <Modal title={title} onClose={onClose}>
      <p className="muted">{text}</p>
      <div className="modal-actions">
        <button className="button secondary" onClick={onClose}>
          {t("取消")}
        </button>
        <button
          className={`button ${danger ? "destructive" : "primary"}`}
          onClick={() => void onConfirm()}
        >
          {t("确认")}
        </button>
      </div>
    </Modal>
  );
}
export function Setting({
  label,
  text,
  children,
}: {
  label: string;
  text?: string;
  children: ReactNode;
}) {
  return (
    <div className="setting-row">
      <div>
        <strong>{label}</strong>
        {text && <p>{text}</p>}
      </div>
      <div className="setting-control">{children}</div>
    </div>
  );
}
export function Toggle({
  checked,
  onChange,
  label,
}: {
  checked: boolean;
  onChange: (value: boolean) => void;
  label: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      className={`toggle ${checked ? "checked" : ""}`}
      onClick={() => onChange(!checked)}
    >
      <span />
    </button>
  );
}
