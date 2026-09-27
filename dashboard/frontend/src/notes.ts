import { createContext } from "react";
import type { Note, NoteKind } from "./types";

export const NOTE_KIND_LABEL: Record<NoteKind, string> = {
  finding: "Finding", remediation: "Remediation work item", security_rule: "Security rule", nat_rule: "NAT rule",
};

export interface NotesApi {
  byTarget: Map<string, Note>;
  save: (kind: NoteKind, key: string, label: string, body: string) => Promise<void>;
  remove: (note: Note) => Promise<void>;
  /** Opens the appendix at this note. */
  openNote: (note: Note) => void;
  /** Goes back to the entry the note is on. */
  openTarget: (note: Note) => void;
}

export const NotesContext = createContext<NotesApi | null>(null);

export const targetId = (kind: NoteKind, key: string) => `${kind}:${key}`;
export const noteAnchor = (n: number) => `note-${n}`;
export const noteRefAnchor = (n: number) => `note-ref-${n}`;

export function noteFor(byTarget: Map<string, Note>, kind: NoteKind, key: string): Note | undefined {
  return byTarget.get(targetId(kind, key));
}

export function indexNotes(notes: Note[]): Map<string, Note> {
  return new Map(notes.map((n) => [targetId(n.target_kind, n.target_key), n]));
}

/** Briefly highlights an element after navigating to it. */
export function flash(el: Element | null) {
  if (!el) return;
  el.scrollIntoView({ behavior: "smooth", block: "center" });
  el.classList.add("note-flash");
  setTimeout(() => el.classList.remove("note-flash"), 1600);
}
