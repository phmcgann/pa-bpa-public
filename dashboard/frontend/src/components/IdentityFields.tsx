import { Building2, Check, Hash, Pencil, Plus, X } from "lucide-react";
import { useMemo, useState, type KeyboardEvent, type MouseEvent } from "react";
import { cn } from "../lib/cn";
import { Button } from "./ui/Button";
import { Popover } from "./ui/Popover";

/** Clicks inside an editor must not trigger the table row's navigation. */
function stop(e: MouseEvent) {
  e.stopPropagation();
}

const triggerBase = cn(
  "inline-flex items-center gap-1.5 max-w-full h-7 px-2 -mx-2 rounded-md text-[13px] border-0 bg-transparent",
  "hover:bg-surface-3 transition-colors",
);

/**
 * Client name as a combobox: type to filter the clients already in use, pick one, or create a
 * new one from what you typed. "Remove client" clears it.
 */
export function ClientCombobox({ value, clients, onSave, compact }: {
  value: string | null;
  clients: string[];
  onSave: (value: string | null) => Promise<void>;
  compact?: boolean;
}) {
  return (
    <Popover
      width={272}
      trigger={({ toggle, ref, open }) => (
        <button
          ref={ref}
          type="button"
          onClick={(e) => { stop(e); toggle(); }}
          aria-haspopup="dialog"
          aria-expanded={open}
          title={value ? "Change client" : "Assign a client"}
          className={cn(triggerBase, value ? "text-fg" : "text-fg-muted")}
        >
          {value ? (
            <>
              {!compact && <Building2 size={14} className="text-fg-muted shrink-0" aria-hidden="true" />}
              <span className="truncate">{value}</span>
            </>
          ) : (
            <>
              <Plus size={14} className="shrink-0" aria-hidden="true" />
              <span>{compact ? "Assign" : "Assign client"}</span>
            </>
          )}
        </button>
      )}
    >
      {(close) => <ClientPicker value={value} clients={clients} onPick={async (v) => { await onSave(v); close(); }} />}
    </Popover>
  );
}

function ClientPicker({ value, clients, onPick }: {
  value: string | null; clients: string[]; onPick: (value: string | null) => Promise<void>;
}) {
  const [query, setQuery] = useState("");
  const [busy, setBusy] = useState(false);
  const [highlight, setHighlight] = useState(0);
  const q = query.trim();
  const matches = useMemo(
    () => clients.filter((c) => c.toLowerCase().includes(q.toLowerCase())),
    [clients, q],
  );
  const canCreate = q.length > 0 && !clients.some((c) => c.toLowerCase() === q.toLowerCase());
  const options: { key: string; label: string; value: string | null; kind: "pick" | "create" }[] = [
    ...matches.map((c) => ({ key: `c:${c}`, label: c, value: c, kind: "pick" as const })),
    ...(canCreate ? [{ key: "create", label: q, value: q, kind: "create" as const }] : []),
  ];

  async function pick(v: string | null) {
    setBusy(true);
    try { await onPick(v); } finally { setBusy(false); }
  }

  function onKey(e: KeyboardEvent) {
    if (e.key === "ArrowDown") { e.preventDefault(); setHighlight((h) => Math.min(h + 1, options.length - 1)); }
    if (e.key === "ArrowUp") { e.preventDefault(); setHighlight((h) => Math.max(h - 1, 0)); }
    if (e.key === "Enter" && options[highlight]) { e.preventDefault(); pick(options[highlight].value); }
  }

  return (
    <div onClick={stop}>
      <input
        autoFocus
        value={query}
        onChange={(e) => { setQuery(e.target.value); setHighlight(0); }}
        onKeyDown={onKey}
        placeholder={clients.length ? "Search or create a client…" : "New client name…"}
        aria-label="Client"
        maxLength={200}
        disabled={busy}
        className="w-full border-0 bg-transparent min-h-9 px-2.5 focus:outline-none focus-visible:outline-none"
      />
      <div className="h-px bg-line -mx-1.5 my-1" />
      <div role="listbox" className="max-h-64 overflow-y-auto">
        {options.length === 0 && (
          <div className="px-2.5 py-2 text-[12px] text-fg-muted">
            {clients.length ? "No clients match." : "No clients yet — type a name to create one."}
          </div>
        )}
        {options.map((o, i) => (
          <button
            key={o.key}
            type="button"
            role="option"
            aria-selected={i === highlight}
            disabled={busy}
            onMouseEnter={() => setHighlight(i)}
            onClick={() => pick(o.value)}
            className={cn(
              "w-full flex items-center gap-2 text-left px-2.5 h-8 rounded-md text-[13px] border-0",
              i === highlight ? "bg-surface-3" : "bg-transparent",
            )}
          >
            {o.kind === "create" ? (
              <>
                <Plus size={14} className="text-fg-muted shrink-0" aria-hidden="true" />
                <span className="truncate">Create <strong className="font-semibold">“{o.label}”</strong></span>
              </>
            ) : (
              <>
                <Building2 size={14} className="text-fg-muted shrink-0" aria-hidden="true" />
                <span className="truncate flex-1">{o.label}</span>
                {o.value === value && <Check size={14} className="text-accent-fg shrink-0" aria-label="Current" />}
              </>
            )}
          </button>
        ))}
      </div>
      {value && (
        <>
          <div className="h-px bg-line -mx-1.5 my-1" />
          <button
            type="button"
            disabled={busy}
            onClick={() => pick(null)}
            className="w-full flex items-center gap-2 text-left px-2.5 h-8 rounded-md text-[13px] border-0 bg-transparent text-fg-2 hover:bg-surface-3"
          >
            <X size={14} className="shrink-0" aria-hidden="true" /> Remove client
          </button>
        </>
      )}
    </div>
  );
}

/** Serial number as read from the file, with manual entry for files that don't carry one. */
export function SerialEdit({ value, onSave, compact }: {
  value: string | null;
  onSave: (value: string | null) => Promise<void>;
  compact?: boolean;
}) {
  return (
    <Popover
      width={260}
      trigger={({ toggle, ref, open }) => (
        <button
          ref={ref}
          type="button"
          onClick={(e) => { stop(e); toggle(); }}
          aria-haspopup="dialog"
          aria-expanded={open}
          title={value ? "Edit serial number" : "Add a serial number"}
          className={cn(triggerBase, "group", value ? "text-fg" : "text-fg-muted")}
        >
          {!compact && <Hash size={14} className="text-fg-muted shrink-0" aria-hidden="true" />}
          <span className="truncate tab-num">{value ?? (compact ? "Add" : "Add serial")}</span>
          {value && <Pencil size={12} className="text-fg-faint opacity-0 group-hover:opacity-100 shrink-0" aria-hidden="true" />}
        </button>
      )}
    >
      {(close) => <SerialForm value={value} onSave={async (v) => { await onSave(v); close(); }} onCancel={close} />}
    </Popover>
  );
}

function SerialForm({ value, onSave, onCancel }: {
  value: string | null; onSave: (v: string | null) => Promise<void>; onCancel: () => void;
}) {
  const [text, setText] = useState(value ?? "");
  const [busy, setBusy] = useState(false);
  async function save() {
    setBusy(true);
    try { await onSave(text.trim() || null); } finally { setBusy(false); }
  }
  return (
    <div className="p-1.5" onClick={stop}>
      <label className="block text-[12px] font-medium text-fg-muted mb-1.5" htmlFor="serial-input">Serial number</label>
      <input
        id="serial-input"
        autoFocus
        value={text}
        onChange={(e) => setText(e.target.value)}
        onKeyDown={(e) => { if (e.key === "Enter") save(); }}
        maxLength={200}
        disabled={busy}
        placeholder="e.g. 016201012345"
        className="w-full tab-num"
      />
      <p className="text-[11px] text-fg-muted mt-1.5 mb-2 leading-4">
        Tech support files and Panorama exports fill this in; plain config exports don't include it.
      </p>
      <div className="flex justify-end gap-2">
        <Button size="sm" variant="ghost" onClick={onCancel} disabled={busy}>Cancel</Button>
        <Button size="sm" variant="primary" onClick={save} disabled={busy}>Save</Button>
      </div>
    </div>
  );
}
