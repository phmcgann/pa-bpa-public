import { Check, Copy, Terminal } from "lucide-react";
import { useMemo, useState } from "react";
import type { CliChoice, FindingCli } from "../types";
import { Button } from "./ui/Button";
import { Popover } from "./ui/Popover";

const BARE = /^[A-Za-z0-9._/:-]+$/;

/** A value as the CLI takes it: object names quoted when needed, free text escaped (its command supplies quotes). */
function render(choice: CliChoice, value: string): string {
  if (!value) return choice.placeholder;
  if (choice.free) return value.replace(/"/g, '\\"');
  return BARE.test(value) ? value : `"${value.replace(/"/g, '\\"')}"`;
}

/** Builds the paste-ready text: `configure`, then every command in order, with duplicates dropped. No commit. */
function buildText(entries: FindingCli[], choices: Map<string, CliChoice>, values: Record<string, string>): string {
  const lines: string[] = [];
  for (const entry of [...entries].sort((a, b) => a.order - b.order)) {
    for (const cmd of entry.commands) {
      const line = cmd.replace(/\{\{(.+?)\}\}/g, (_, key: string) => {
        const choice = choices.get(key);
        return choice ? render(choice, values[key] ?? "") : `<${key.toUpperCase()}>`;
      });
      if (!lines.includes(line)) lines.push(line);
    }
  }
  return ["configure", ...lines].join("\n");
}

async function copy(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Clipboard API unavailable (plain-HTTP deployments): fall back to a hidden textarea.
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand("copy");
    ta.remove();
    return ok;
  }
}

/** Commands for one finding or a whole work item, with inputs for the values the config can't supply. */
export function CliPanel({ entries, title, extra }: { entries: FindingCli[]; title: string; extra?: string }) {
  const choices = useMemo(() => {
    const m = new Map<string, CliChoice>();
    for (const e of entries) for (const c of e.choices) if (!m.has(c.key)) m.set(c.key, c);
    return m;
  }, [entries]);
  const [values, setValues] = useState<Record<string, string>>(() => {
    const init: Record<string, string> = {};
    // A recommended default, or the only existing object to pick from.
    for (const c of choices.values()) {
      if (c.default) init[c.key] = c.default;
      else if (!c.free && c.options.length === 1) init[c.key] = c.options[0];
    }
    return init;
  });
  const [copied, setCopied] = useState(false);
  const text = buildText(entries, choices, values);
  const unfilled = [...choices.values()].filter((c) => !values[c.key]).length;
  const notes = [...new Set(entries.map((e) => e.note).filter((n): n is string => !!n))];

  return (
    <div className="flex flex-col gap-3 p-4 text-[12px]">
      <div>
        <div className="text-[13px] font-semibold text-fg">{title}</div>
        <p className="text-fg-muted m-0 mt-0.5 leading-5">
          Paste at the firewall's CLI. It enters configure mode and stages the changes; review them with{" "}
          <code>show | compare</code>, then <code>commit</code> yourself.
          {extra && <> {extra}</>}
        </p>
      </div>

      {choices.size > 0 && (
        <div className="grid gap-2">
          {[...choices.values()].map((c) => (
            <label key={c.key} className="grid gap-1">
              <span className="text-fg-2 font-medium">{c.label}</span>
              {!c.free && c.options.length > 0 ? (
                <select
                  value={values[c.key] ?? ""}
                  onChange={(e) => setValues({ ...values, [c.key]: e.target.value })}
                  className="h-8"
                >
                  <option value="">Choose… (leaves {c.placeholder})</option>
                  {c.options.map((o) => <option key={o} value={o}>{o}</option>)}
                </select>
              ) : (
                <input
                  value={values[c.key] ?? ""}
                  onChange={(e) => setValues({ ...values, [c.key]: e.target.value })}
                  placeholder={c.placeholder}
                  className="h-8 px-2 rounded-md border border-line-strong bg-surface text-fg"
                />
              )}
              {!c.free && c.options.length === 0 && (
                <span className="text-fg-muted">None defined on this firewall yet: create one, or type its name.</span>
              )}
            </label>
          ))}
        </div>
      )}

      <pre className="m-0 p-3 rounded-md bg-surface-3 text-fg text-[12px] leading-5 overflow-auto max-h-72 whitespace-pre font-mono">
        {text}
      </pre>

      {notes.map((n) => <p key={n} className="m-0 text-fg-2 leading-5">{n}</p>)}

      <div className="flex items-center justify-between gap-3">
        <span className={unfilled ? "text-warning-fg" : "text-fg-muted"}>
          {unfilled ? `${unfilled} value${unfilled === 1 ? "" : "s"} still to fill in` : "Verify on a lab firewall before first use."}
        </span>
        <Button
          size="sm"
          variant="primary"
          onClick={async () => {
            if (await copy(text)) {
              setCopied(true);
              setTimeout(() => setCopied(false), 1800);
            }
          }}
        >
          {copied ? <Check size={13} /> : <Copy size={13} />}
          {copied ? "Copied" : "Copy"}
        </Button>
      </div>
    </div>
  );
}

/** A button that opens the CLI panel for the given commands. */
export function CliButton({ entries, title, label = "CLI", extra, variant = "ghost" }: {
  entries: FindingCli[];
  title: string;
  label?: string;
  extra?: string;
  variant?: "ghost" | "secondary";
}) {
  if (entries.length === 0) return null;
  return (
    <Popover
      width={480}
      align="end"
      trigger={({ toggle, ref }) => (
        <Button ref={ref} size="sm" variant={variant} onClick={toggle} title="PAN-OS CLI commands for this fix" className="no-print">
          <Terminal size={13} />{label}
        </Button>
      )}
    >
      {() => (
        <div className="w-[480px] max-w-[calc(100vw-16px)] max-h-[calc(100vh-16px)] overflow-auto">
          <CliPanel entries={entries} title={title} extra={extra} />
        </div>
      )}
    </Popover>
  );
}
