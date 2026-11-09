import { execFileSync, spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { RawSpan } from "./types";

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/**
 * The plugin root. The compiled plugin code lives at the repo root (tsc
 * output) or in `.lmstudio/dev.js` (lms dev bundle) — the worker script is
 * always at `<plugin root>/sidecar/worker.mjs`.
 */
function pluginRoot(): string {
  const candidates = [__dirname, path.join(__dirname, "..")];
  for (const dir of candidates) {
    if (fs.existsSync(path.join(dir, "sidecar", "worker.mjs"))) {
      return dir;
    }
  }
  throw new Error(
    `sidecar worker script not found (tried: ${candidates.map(c => path.join(c, "sidecar", "worker.mjs")).join(", ")})`,
  );
}

const WORKER_PATH = path.join(pluginRoot(), "sidecar", "worker.mjs");

/**
 * Cache directory for the re-signed runner binary. The copy is named
 * `pii-redact-node` so the Gatekeeper prompt (if any) identifies it clearly.
 */
const CACHE_DIR = path.join(os.homedir(), ".cache", "pii-redact");
const RUNNER_PATH = path.join(CACHE_DIR, "pii-redact-node");

// ---------------------------------------------------------------------------
// Runner preparation
// ---------------------------------------------------------------------------

/**
 * Prepare a re-signed copy of the plugin runner binary.
 *
 * LM Studio's plugin runner is signed with a Team ID and enforces macOS
 * library validation, so native addons (koffi) cannot be loaded in-process
 * (lmstudio-bug-tracker#1494). An ad-hoc re-signed copy drops the hardened
 * runtime flag, which disables library validation.
 *
 * Steps:
 * 1. Copy the runner binary into the cache dir (re-done when the source
 *    binary changes, e.g. after an LM Studio update).
 * 2. Strip all extended attributes — macOS kills re-signed binaries that
 *    still carry `provenance`/`quarantine` xattrs inherited from the app
 *    bundle.
 * 3. Ad-hoc re-sign (`codesign --force --sign -`).
 */
function ensureRunner(): string {
  const source = process.execPath;
  const srcStat = fs.statSync(source);

  let needsRebuild = true;
  try {
    const dstStat = fs.statSync(RUNNER_PATH);
    needsRebuild =
      dstStat.size !== srcStat.size || Math.floor(dstStat.mtimeMs) !== Math.floor(srcStat.mtimeMs);
  } catch {
    // Copy does not exist yet
  }

  if (needsRebuild) {
    fs.mkdirSync(CACHE_DIR, { recursive: true });
    fs.copyFileSync(source, RUNNER_PATH);
    fs.chmodSync(RUNNER_PATH, 0o755);
    // macOS-only helpers — the sidecar is only used on macOS (where library
    // validation blocks native addons); on Linux/Windows the in-process path
    // works and this code is never reached.
    execFileSync("/usr/bin/xattr", ["-c", RUNNER_PATH]);
    try {
      // Suppress codesign's normal output ("replacing existing signature") —
      // only failures are surfaced.
      execFileSync("/usr/bin/codesign", ["--force", "--sign", "-", RUNNER_PATH], {
        stdio: ["ignore", "ignore", "pipe"],
      });
    } catch (err) {
      const stderr = (err as { stderr?: Buffer }).stderr?.toString().trim();
      throw new Error(
        `failed to re-sign the sidecar runner copy (${RUNNER_PATH}): ` +
          (stderr || String(err)),
      );
    }
  }
  return RUNNER_PATH;
}

// ---------------------------------------------------------------------------
// Worker lifecycle
// ---------------------------------------------------------------------------

interface PendingRequest {
  resolve: (value: unknown) => void;
  reject: (err: Error) => void;
}

let worker: ChildProcessWithoutNullStreams | null = null;
let nextId = 1;
const pending = new Map<number, PendingRequest>();

function spawnWorker(): ChildProcessWithoutNullStreams {
  const runner = ensureRunner();
  const child = spawn(runner, [WORKER_PATH], {
    cwd: pluginRoot(),
    stdio: ["pipe", "pipe", "pipe"],
  });

  child.on("exit", () => {
    // Reject all in-flight requests and drop the worker so the next
    // detection spawns a fresh one.
    for (const p of pending.values()) {
      p.reject(new Error("sidecar worker exited unexpectedly"));
    }
    pending.clear();
    worker = null;
  });

  // Worker stderr → plugin stderr (shows up in the lms dev terminal)
  child.stderr.on("data", chunk => {
    process.stderr.write(chunk);
  });

  let outBuf = "";
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", chunk => {
    outBuf += chunk;
    let idx;
    while ((idx = outBuf.indexOf("\n")) !== -1) {
      const line = outBuf.slice(0, idx);
      outBuf = outBuf.slice(idx + 1);
      if (line.trim() === "") continue;
      handleWorkerMessage(line);
    }
  });

  return child;
}

function handleWorkerMessage(line: string): void {
  let msg: {
    type: string;
    id: number | null;
    spans?: RawSpan[];
    message?: string;
  };
  try {
    msg = JSON.parse(line);
  } catch {
    process.stderr.write(`[pii-redact] sidecar sent invalid JSON: ${line}\n`);
    return;
  }
  if (msg.id === null || msg.id === undefined) {
    process.stderr.write(`[pii-redact] sidecar error: ${msg.message ?? "unknown"}\n`);
    return;
  }
  const p = pending.get(msg.id);
  if (p === undefined) {
    // Late response (e.g. after an abort) — ignore
    return;
  }
  pending.delete(msg.id);
  if (msg.type === "result" && msg.spans !== undefined) {
    p.resolve(msg.spans);
  } else if (msg.type === "ready") {
    p.resolve(undefined);
  } else {
    p.reject(new Error(msg.message ?? "sidecar request failed"));
  }
}

function getWorker(): ChildProcessWithoutNullStreams {
  if (worker === null) {
    worker = spawnWorker();
  }
  return worker;
}

function request(type: "warmup" | "detect", text?: string): Promise<unknown> {
  const child = getWorker();
  const id = nextId++;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    child.stdin.write(JSON.stringify({ type, id, text }) + "\n");
  });
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Detect PII via the sidecar worker. Returns spans in document order, using
 * Redact's own labels.
 */
export async function detectViaSidecar(text: string): Promise<RawSpan[]> {
  return (await request("detect", text)) as RawSpan[];
}

/**
 * Warm up the sidecar: spawn the worker and trigger the Redact model load
 * (weights download on first use). Called fire-and-forget from main() so the
 * first preprocessor request does not pay the startup cost.
 */
export async function warmSidecar(): Promise<void> {
  await request("warmup");
}
