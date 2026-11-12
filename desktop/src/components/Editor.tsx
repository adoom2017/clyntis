import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { LoaderCircle } from "lucide-react";
import { t } from "../i18n";
import { type Profile } from "../types";
import { Modal } from "../components/common";

type YamlProblem = { line: number; column: number; message: string };
/** Editor text metrics, kept in step with `.yaml-editor` in styles.css. */
const editorPadding = 1 + 12; // border + padding
const editorLine = 12 * 1.6;
export function Editor({
  profile,
  onClose,
  onSave,
}: {
  profile: Profile;
  onClose: () => void;
  onSave: (yaml: string) => Promise<boolean>;
}) {
  const [yaml, setYaml] = useState(profile.pending ?? profile.yaml);
  const [saving, setSaving] = useState(false);
  const [failed, setFailed] = useState(false);
  const [problem, setProblem] = useState<YamlProblem | null>(null);
  const [scroll, setScroll] = useState(0);
  const area = useRef<HTMLTextAreaElement>(null);
  // Check while typing, after a short pause; a stale answer is ignored.
  useEffect(() => {
    let current = true;
    const timer = setTimeout(() => {
      invoke<YamlProblem | null>("check_yaml", { yaml })
        .then((found) => current && setProblem(found ?? null))
        .catch(() => current && setProblem(null));
    }, 250);
    return () => {
      current = false;
      clearTimeout(timer);
    };
  }, [yaml]);
  const reveal = () => {
    const editor = area.current;
    if (!problem || !editor) return;
    const lines = yaml.split("\n");
    const offset =
      lines.slice(0, problem.line - 1).reduce((n, l) => n + l.length + 1, 0) +
      Math.min(problem.column - 1, lines[problem.line - 1]?.length ?? 0);
    editor.focus();
    editor.setSelectionRange(offset, offset);
    editor.scrollTop = Math.max(
      0,
      (problem.line - 1) * editorLine - editor.clientHeight / 2,
    );
  };
  return (
    <Modal
      title={t("编辑 · {name}", { name: profile.name })}
      onClose={onClose}
      wide
    >
      <p className="small muted">
        {t("保存时会校验，点「应用更新」后生效。内容含节点凭据，注意保密。")}
      </p>
      <div className={`yaml-field${problem ? " invalid" : ""}`}>
        {problem && (
          <div
            className="yaml-error-line"
            aria-hidden="true"
            style={{
              top: editorPadding + (problem.line - 1) * editorLine - scroll,
              height: editorLine,
            }}
          />
        )}
        <textarea
          ref={area}
          className="yaml-editor"
          aria-label={t("YAML 配置")}
          aria-invalid={problem ? true : undefined}
          aria-describedby={problem ? "yaml-problem" : undefined}
          value={yaml}
          onChange={(e) => setYaml(e.target.value)}
          onScroll={(e) => setScroll(e.currentTarget.scrollTop)}
          spellCheck={false}
          wrap="off"
        />
      </div>
      {problem && (
        <p className="inline-error yaml-problem" id="yaml-problem" role="alert">
          <button type="button" className="link-button" onClick={reveal}>
            {t("第 {line} 行第 {column} 列", {
              line: problem.line,
              column: problem.column,
            })}
          </button>
          {t("：{message}", { message: problem.message })}
        </p>
      )}
      {failed && (
        <p className="inline-error" role="alert">
          {t("保存失败，原配置未改动。关闭此窗口查看原因。")}
        </p>
      )}
      <div className="modal-actions">
        <button className="button secondary" onClick={onClose}>
          {t("取消")}
        </button>
        <button
          className="button primary"
          disabled={saving || problem !== null}
          title={problem ? t("先修正 YAML 格式错误") : undefined}
          onClick={() => {
            setSaving(true);
            void onSave(yaml)
              .then((ok) => setFailed(!ok))
              .finally(() => setSaving(false));
          }}
        >
          {saving && <LoaderCircle className="spin" size={16} />}
          {t("保存")}
        </button>
      </div>
    </Modal>
  );
}
