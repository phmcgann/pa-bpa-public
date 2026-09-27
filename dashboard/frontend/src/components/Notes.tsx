import { CornerDownLeft, StickyNote, Trash2 } from "lucide-react";
import { useContext, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { cn } from "../lib/cn";
import { NOTE_KIND_LABEL, NotesContext, noteAnchor, noteFor, noteRefAnchor, type NotesApi } from "../notes";
import type { Note, NoteKind } from "../types";
import { Button } from "./ui/Button";
import { Popover } from "./ui/Popover";

/**
 * Analyst notes on report entries (a finding, a remediation work item, a security or NAT rule),
 * shown as numbered endnotes. An entry carries a numbered marker: hovering it shows the note,
 * clicking it opens the Notes appendix at that note. The appendix prints at the end of the report.
 */

/** The numbered marker on an entry that has a note; renders nothing otherwise. */
export function NoteRef({ kind, targetKey }: { kind: NoteKind; targetKey: string }) {
  const ctx = useContext(NotesContext);
  const note = ctx && noteFor(ctx.byTarget, kind, targetKey);
  const [hover, setHover] = useState(false);
  const ref = useRef<HTMLButtonElement>(null);
  if (!ctx || !note) return null;
  // A superscript reference number, as in a printed document: it sits right after the entry's text.
  return (
    <sup className="note-ref-sup">
      <button
        ref={ref}
        type="button"
        id={noteRefAnchor(note.number)}
        onClick={() => ctx.openNote(note)}
        onMouseEnter={() => setHover(true)}
        onMouseLeave={() => setHover(false)}
        onFocus={() => setHover(true)}
        onBlur={() => setHover(false)}
        aria-label={`Note ${note.number}: ${note.body}`}
        className={cn(
          "note-ref inline p-0 m-0 ml-[0.05em] bg-transparent border-0 rounded-none cursor-pointer",
          "text-[1em] leading-none font-semibold [font-variant-numeric:proportional-nums] text-accent-fg hover:underline underline-offset-2",
        )}
      >
        {note.number}
      </button>
      {hover && <NoteHoverCard note={note} anchor={ref.current} />}
    </sup>
  );
}

function NoteHoverCard({ note, anchor }: { note: Note; anchor: HTMLElement | null }) {
  const card = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null);
  useLayoutEffect(() => {
    const a = anchor?.getBoundingClientRect();
    const c = card.current;
    if (!a || !c) return;
    const w = c.offsetWidth, h = c.offsetHeight;
    const left = Math.max(8, Math.min(a.left - 12, window.innerWidth - w - 8));
    const top = a.bottom + 6 + h > window.innerHeight - 8 ? a.top - h - 6 : a.bottom + 6;
    setPos({ top: Math.max(8, top), left });
  }, [anchor]);
  return createPortal(
    <div
      ref={card}
      role="tooltip"
      style={{ top: pos?.top ?? -9999, left: pos?.left ?? -9999 }}
      className="fixed z-50 w-[340px] max-w-[calc(100vw-16px)] rounded-lg border border-line-strong bg-surface shadow-pop p-3 pointer-events-none no-print"
    >
      <div className="text-[11px] font-semibold uppercase tracking-[0.08em] text-accent-fg mb-1">Note {note.number}</div>
      <div className="text-[13px] leading-5 text-fg whitespace-pre-wrap break-words max-h-64 overflow-hidden">{note.body}</div>
      <div className="text-[11px] text-fg-muted mt-2">Click to open it in Notes</div>
    </div>,
    document.body,
  );
}

/** Add or edit the note on an entry. `label` says in words what the entry is, for the appendix. */
export function NoteButton({ kind, targetKey, label, className, iconOnly }: {
  kind: NoteKind; targetKey: string; label: string; className?: string;
  /** Just the icon, for tight table cells (the entry's marker already shows the number). */
  iconOnly?: boolean;
}) {
  const ctx = useContext(NotesContext);
  if (!ctx) return null;
  const note = noteFor(ctx.byTarget, kind, targetKey);
  return (
    <Popover
      align="end"
      width={380}
      trigger={({ toggle, ref }) => (
        <Button
          ref={ref as (el: HTMLButtonElement | null) => void}
          size="sm"
          variant="ghost"
          onClick={toggle}
          iconOnly={iconOnly}
          aria-label={note ? `Edit note ${note.number}` : "Add a note"}
          title={note ? `Edit note ${note.number}` : "Add a note — it's listed in the report's Notes appendix"}
          className={cn("no-print", className)}
        >
          <StickyNote size={13} />{!iconOnly && (note ? `Note ${note.number}` : "Note")}
        </Button>
      )}
    >
      {(close) => <NoteEditor ctx={ctx} note={note} kind={kind} targetKey={targetKey} label={label} onDone={close} />}
    </Popover>
  );
}

function NoteEditor({ ctx, note, kind, targetKey, label, onDone }: {
  ctx: NotesApi; note?: Note; kind: NoteKind; targetKey: string; label: string; onDone: () => void;
}) {
  const [body, setBody] = useState(note?.body ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function run(action: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await action();
      onDone();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  }
  return (
    <form
      className="p-4 flex flex-col gap-3 text-[13px]"
      onSubmit={(e) => { e.preventDefault(); if (body.trim()) run(() => ctx.save(kind, targetKey, label, body)); }}
    >
      <div>
        <div className="font-semibold text-fg">{note ? `Note ${note.number}` : "Add a note"}</div>
        <div className="text-[12px] text-fg-muted mt-0.5 line-clamp-2">{NOTE_KIND_LABEL[kind]}: {label}</div>
      </div>
      <textarea
        autoFocus
        value={body}
        onChange={(e) => setBody(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter" && (e.metaKey || e.ctrlKey) && body.trim()) {
            e.preventDefault();
            run(() => ctx.save(kind, targetKey, label, body));
          }
        }}
        rows={6}
        maxLength={10000}
        placeholder="Context, a client decision, a planned fix… Shown in the Notes appendix and printed with the report."
        className="w-full rounded-md border border-line-strong bg-surface text-fg p-2 leading-5 resize-y"
      />
      {error && <div className="text-critical-fg text-[12px]">{error}</div>}
      <div className="flex items-center gap-2">
        {note && (
          <Button type="button" size="sm" variant="ghost" disabled={busy} onClick={() => run(() => ctx.remove(note))}>
            <Trash2 size={13} />Delete
          </Button>
        )}
        <span className="ml-auto text-[11px] text-fg-muted">Ctrl+Enter to save</span>
        <Button type="button" size="sm" variant="ghost" onClick={onDone}>Cancel</Button>
        <Button type="submit" size="sm" variant="primary" disabled={busy || !body.trim()}>Save</Button>
      </div>
    </form>
  );
}

/** The appendix: every note in number order, with what it's about. */
export function NotesAppendix({ notes }: { notes: Note[] }) {
  const ctx = useContext(NotesContext);
  return (
    <ol className="list-none m-0 p-0 flex flex-col">
      {notes.map((n) => (
        <li
          key={n.id}
          id={noteAnchor(n.number)}
          className="note-entry keep-together border-t border-divider first:border-t-0 py-4 flex gap-4 scroll-mt-24"
        >
          <div className="shrink-0 w-8 h-8 rounded-full bg-accent-soft text-accent-fg font-semibold tab-num flex items-center justify-center text-[14px]">
            {n.number}
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-start gap-x-3 gap-y-1">
              <div className="min-w-0 flex-1">
                <div className="text-[11px] font-semibold uppercase tracking-[0.08em] text-fg-muted">
                  {NOTE_KIND_LABEL[n.target_kind]}
                </div>
                <div className="text-[13px] font-medium text-fg leading-5 break-words">{n.target_label}</div>
              </div>
              {ctx && (
                <span className="no-print inline-flex items-center gap-1">
                  <Button size="sm" variant="ghost" onClick={() => ctx.openTarget(n)} title="Go to the entry this note is on">
                    <CornerDownLeft size={13} />Go to entry
                  </Button>
                  <NoteButton kind={n.target_kind} targetKey={n.target_key} label={n.target_label} />
                </span>
              )}
            </div>
            <p className="text-[13px] text-fg-2 leading-5 mt-2 mb-0 whitespace-pre-wrap break-words max-w-3xl">{n.body}</p>
            <div className="text-[11px] text-fg-muted mt-1.5">
              {n.updated_at !== n.created_at ? "Edited " : "Added "}
              {new Date(n.updated_at + "Z").toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })}
              {n.carried_from && (
                <> · carried over from the{" "}
                  {new Date(n.carried_from.uploaded_at + "Z").toLocaleDateString(undefined, { dateStyle: "medium" })} run</>
              )}
            </div>
          </div>
        </li>
      ))}
    </ol>
  );
}
