// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

// What every page reads, and the words for it. One definition each: "let in"
// is a read or fetch Sluse admitted, counted by distinct file.

import type { AuditRecord, ConfigView, InventoryRow, Provenance, RunState, SourceView, VolumeAlert } from "./api.js";

export interface Data {
  state: RunState;
  view: ConfigView;
  /** This session's records, oldest first. */
  journal: AuditRecord[];
  alerts: VolumeAlert[];
  /** Every session's publishes, newest first (Q37). */
  provenance: Provenance[];
  /** Every session's copies. */
  inventory: InventoryRow[];
}

/** Sources read as the work account: they wait for a sign-in (Q8). */
const CLOUD = ["sharepoint", "onedrive"];
export const cloud = (d: Data): string[] => d.view.sources.filter((s) => CLOUD.includes(s.kind)).map((s) => s.name);
/** Sources read as the Windows account: file shares, Sluse Inputs. */
export const local = (d: Data): string[] => d.view.sources.filter((s) => !CLOUD.includes(s.kind)).map((s) => s.name);
export const sourceNames = (d: Data): string[] => d.view.sources.map((s) => s.name);

/** When this session began: its first record, the sources it listed at start. */
export const sessionStart = (d: Data): string | undefined => d.journal[0]?.ts;

/** The source a path belongs to: `finance/2026/Q3/x.csv` is `finance`. */
export const sourceOf = (path: string): string => path.split("/")[0] ?? path;
/** The path within its source. */
export const within = (path: string): string => path.split("/").slice(1).join("/") || path;

/** Reads and fetches Sluse let in, this session, oldest first. */
export const letIn = (d: Data): AuditRecord[] =>
  d.journal.filter((r) => (r.op === "read" || r.op === "fetch") && r.outcome === "admitted");

/** What a source is, in words: "SharePoint library, 2 folders". */
export function kindWords(s: SourceView): string {
  const n = s.scopes.length;
  switch (s.kind) {
    case "sharepoint": return `SharePoint library${n ? `, ${n} folder${n === 1 ? "" : "s"}` : ""}`;
    case "smb": return `File share${n ? `, ${n} folder${n === 1 ? "" : "s"}` : ""}`;
    case "onedrive": return "Your Sluse folder in OneDrive";
    case "inputs": return "Sluse Inputs on your computer";
    default: return `Folder on this device${n ? `, ${n} folder${n === 1 ? "" : "s"}` : ""}`;
  }
}

/** Its icon. */
export const kindIcon = (kind: string): string =>
  ({ sharepoint: "library", smb: "server", onedrive: "cloud", inputs: "inbox" })[kind] ?? "folder";

/**
 * A publish's folder in Sluse Artifacts and the file's name in it, from its
 * record's path, `artifacts/<folder>/<name>`, as the broker names the folder
 * on the host (D-031 point 5 amended): `2026-10-19 14.32 q3-variance`.
 */
export function folderOf(path: string, artifact?: string): string | undefined {
  const rest = path.startsWith("artifacts/") ? path.slice("artifacts/".length) : path;
  if (artifact && rest.endsWith(`/${artifact}`)) return rest.slice(0, -artifact.length - 1);
  return rest.includes("/") ? rest.split("/")[0] : undefined;
}

/** Each op in words (the Record page, the work view). */
export const OP: Record<string, string> = {
  read: "Read", fetch: "Fetched", reread: "Re-read a copy", publish: "Published", metadata: "Looked up details",
  list: "Opened a folder", sources: "Listed the sources", alert: "Volume alert", clear: "Deleted the copies",
  signin: "Signed in", signout: "Signed out", scope: "Read the scope", tail: "Read the computer's record", journal: "Read this record",
};

/**
 * A reason code in words: what happened, and what the person can do. A
 * refusal's hidden reason is said honestly: it is in the Event Log.
 */
export function reasonWords(code: string | undefined, outcome: string): string {
  const said: Record<string, string> = {
    OFFICE_ENCRYPTED: "Arrived encrypted. Sluse gave the box no key to open it.",
    NOT_UTF8_TEXT: "Its text could not be shown to the agent: not text",
    MODIFIED_SINCE_ADMISSION: "Changed since it was let in",
    NO_PROVENANCE: "No provenance: not let in through Sluse, or its provenance file is gone",
    SOURCE_NOT_ADMITTED: "Named a source this box never let in",
    HASH_MISMATCH: "The file changed while it was being published",
    SOURCE_UNAVAILABLE: "The source did not answer",
    SIGN_IN_REQUIRED: "Sluse needed a sign-in it did not have",
    TOO_LARGE: "Larger than Sluse lets into the box",
    NOT_FOUND: "Not there at the source",
    BROKER_UNREACHABLE: "Sluse on your computer did not answer",
  };
  if (code && said[code]) return said[code];
  // A code with no words yet: said plainly, with the code under it.
  if (code && /^[A-Z_]+$/.test(code)) return outcome === "refused" ? "Refused by Sluse" : "It did not finish";
  if (code?.startsWith("rendered by")) return "Rendered by Sluse from the agent's Markdown";
  if (code?.startsWith("cleared ")) {
    const m = /cleared (\d+) file\(s\), (\d+) failed/.exec(code);
    if (m) return `${m[1]} cop${m[1] === "1" ? "y" : "ies"} deleted, ${m[2] === "0" ? "none" : m[2]} failed`;
  }
  if (outcome === "refused" && !code) return "The reason is in this computer's Event Log, which your IT department can read";
  return code ?? "";
}

/** The pill for an outcome: Let in, Published, Done, Refused, Error, Alert. */
export function outcomePill(r: AuditRecord): [string, string] {
  if (r.outcome === "refused") return ["refused", "Refused"];
  if (r.outcome === "error") return ["error", "Error"];
  if (r.outcome === "raised") return ["info", "Alert"];
  if (r.op === "publish") return ["published", "Published"];
  if (r.op === "read" || r.op === "fetch") return ["admitted", "Let in"];
  return ["done", "Done"];
}
