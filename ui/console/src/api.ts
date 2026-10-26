// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

// The console's view of the endpoint's loopback API.
//
// These types mirror `sluse-endpoint/src/console/api.rs` and the wire types in
// `sluse-proto`. They are hand-written rather than generated: the crate already
// emits a JSON Schema for the config, and adding a second generator to keep a
// dozen shapes in step is more machinery than the shapes are worth. When the
// API changes, this file changes in the same commit.

export type Outcome = "admitted" | "refused" | "error" | "raised";

export type Op =
  | "read" | "fetch" | "reread" | "publish" | "metadata"
  | "list" | "sources" | "alert" | "clear" | "signin" | "signout" | "scope" | "tail" | "journal";

export interface UserRef {
  kind: "osProcess" | "entra";
  name: string;
}

export interface GateServing {
  status: "serving";
  postureId: string;
  configVersion: string;
  sessions: number;
  /** Who the box is signed in as (D-022). Absent when nobody is. */
  signedIn?: UserRef;
  /** The person signed out in the box, and nobody since (Q7). */
  signedOut: boolean;
  /** Sluse's count for each source in the volume window (Q36). */
  volume: SourceCount[];
}

export interface SourceCount {
  source: string;
  files: number;
  bytes: number;
}

export interface GateUnreachable {
  status: "unreachable";
  detail: string;
}

export interface RunState {
  boxId: string;
  session: string;
  configVersion: string;
  user: UserRef;
  maxReadBytes: number;
  sources: number;
  gate: GateServing | GateUnreachable;
  /** A development device: out-of-scope entries and the host's record. */
  local: boolean;
  deployment?: { id: string; name: string; revision: number };
}

export interface SourceView {
  name: string;
  kind: string;
  address: string;
  sensitivity: number;
  sensitivityName: string;
  scopes: string[];
  /**
   * The last observation of whether the source answered (D-015 point 4).
   * Not drawn: the console's copy of this view is taken at startup, so it
   * would show an old observation as though it were the current one.
   */
  lastSeen?: { reachable: boolean; at: string };
}

export interface VolumeConfig {
  admissions: number;
  windowSeconds: number;
  /** Bytes in the same window before an alert (D-016). Absent: not watched. */
  bytes?: number;
}

export interface ConfigView {
  sources: SourceView[];
  maxReadBytes: number;
  volume: VolumeConfig;
}

export interface ListEntry {
  name: string;
  kind: "file" | "directory";
  size?: number;
  modified?: string;
  /** False is what gets greyed. The agent never receives a false one. */
  inScope: boolean;
}

export interface ListResponse {
  path: string;
  entries: ListEntry[];
}

export interface LineageItem {
  path: string;
  hash: string;
  admissionId?: string;
  /** What became of it in the box; on a publish's `lineage` only (D-055). */
  state?: "read" | "unread" | "fetched" | "encrypted";
}

export interface AuditRecord {
  writer: "core" | "endpoint";
  boxId: string;
  user: UserRef;
  configVersion: string;
  sessionId: string;
  ts: string;
  op: Op;
  pathRequested: string;
  pathResolved?: string;
  scope?: string;
  capability: "bytes" | "url";
  outcome: Outcome;
  reason?: string;
  hash?: string;
  bytes?: number;
  admissionId?: string;
  publishId?: string;
  artifact?: string;
  lineage?: LineageItem[];
  sources?: LineageItem[];
  label?: string;
  postureId?: string;
}

export interface Provenance {
  sessionId: string;
  /** `artifacts/<folder>/<name>`. */
  path: string;
  reason?: string;
  publishId?: string;
  artifact?: string;
  hash?: string;
  bytes?: number;
  at: string;
  outcome: Outcome;
  /** The agent's declaration; absent on a record from before D-055. */
  sources?: LineageItem[];
  /** Everything admitted in the session, each with its state. */
  lineage: LineageItem[];
}

/**
 * What the source says about an admitted file, against what was admitted then.
 *
 * `unknown` is not a hedge, it is the answer when nobody could be asked — and
 * the console draws it as an absence rather than a colour, because a console
 * that showed "current" after failing to ask would be worse than one that said
 * nothing.
 */
export type InventoryState =
  | "current" | "stale" | "orphaned" | "unknown" | "missing";

export interface InventoryRow {
  path: string;
  source: string;
  hash: string;
  admissionId?: string;
  admittedAt: string;
  bytes?: number;
  local: string;
  localPresent: boolean;
  /** The sidecar beside the copy names this admission (D-019 point 3). */
  sidecar: boolean;
  state: InventoryState;
  checkedAt?: string;
}

export interface VolumeAlert {
  source: string;
  sessionId: string;
  /**
   * **Distinct content hashes** admitted inside the window, not a count of
   * admissions. Re-reading one file does not move it, which is the measure the
   * Gate Core raises an alert on — so it is the measure the meter draws.
   */
  count: number;
  windowSeconds: number;
  openedAt: string;
  /** Absent while the alert is open. */
  closedAt?: string;
  /** Gate Core's own summary, e.g. `tender/ (27 files, 60 s)`. */
  summary: string;
}

export interface AuditTailResponse {
  records: AuditRecord[];
}

export interface Cleared {
  files: number;
  bytes: number;
  failed: string[];
}

/** A refusal from the endpoint or Gate Core, passed through unblinded. */
export interface ApiFailure {
  code: string;
  [field: string]: unknown;
}

export class ApiError extends Error {
  constructor(readonly status: number, readonly failure: ApiFailure) {
    super(`${failure.code}`);
  }
}

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  // Every POST says it is the console's own page; the server refuses one
  // that does not, so another page in the box's browser cannot act here.
  const headers = new Headers(init?.headers);
  headers.set("x-sluse-console", "1");
  const res = await fetch(path, { ...init, headers });
  if (!res.ok) {
    let failure: ApiFailure = { code: `HTTP_${res.status}` };
    try {
      failure = (await res.json()) as ApiFailure;
    } catch {
      // A response that is not JSON is still a failure worth naming; the
      // status code is what there is.
    }
    throw new ApiError(res.status, failure);
  }
  return (await res.json()) as T;
}

export const api = {
  state: () => call<RunState>("/api/state"),
  sources: () => call<ConfigView>("/api/sources"),
  list: (path: string) =>
    call<ListResponse>(`/api/list?path=${encodeURIComponent(path)}`),
  journal: () => call<AuditRecord[]>("/api/journal"),
  provenance: () => call<Provenance[]>("/api/provenance"),
  inventory: () => call<InventoryRow[]>("/api/inventory"),
  /** Ask the source about one copy (Q33): the page counts the answers. */
  check: (path: string) => call<InventoryRow>("/api/inventory/check", {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ path }),
  }),
  clear: () => call<Cleared>("/api/inventory/clear", { method: "POST" }),
  alerts: () => call<VolumeAlert[]>("/api/alerts"),
  audit: (limit = 50) => call<AuditTailResponse>(`/api/audit?limit=${limit}`),
  /** Open an app in the box (D-027): one of a fixed list, never a command. */
  launch: async (app: LaunchApp): Promise<void> => {
    const res = await fetch("/api/launch", {
      method: "POST",
      headers: { "content-type": "application/json", "x-sluse-console": "1" },
      body: JSON.stringify({ app }),
    });
    if (!res.ok) throw new ApiError(res.status, await res.json().catch(() => ({ code: `HTTP_${res.status}` })));
  },
};

export type LaunchApp = "terminal" | "claude-code" | "codex" | "vibe" | "claude-desktop";
