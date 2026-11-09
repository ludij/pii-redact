// Sidecar worker for the pii-redact LM Studio plugin.
//
// LM Studio's plugin runner is signed with a Team ID and enforces macOS
// library validation, so native Node addons (koffi, used by the Redact
// model's native core) cannot be loaded in-process — see lmstudio-bug-tracker
// issue #1494. This worker runs under a re-signed copy of the runner binary,
// where library validation does not apply, and exposes Redact detection over
// a JSON-line protocol on stdin/stdout.
//
// Protocol (one JSON object per line):
//   → { "type": "warmup", "id": 1 }
//   ← { "type": "ready",  "id": 1 }
//   → { "type": "detect", "id": 2, "text": "..." }
//   ← { "type": "result", "id": 2, "spans": [{ "original": "...", "type": "EMAIL" }] }
//   ← { "type": "error",  "id": 2, "message": "..." }   (on failure)
//
// Nothing but JSON lines may be written to stdout — logging goes to stderr.

import { Redact, ALL_LABELS } from "@desert-ant-labs/redact/native";

let instance = null;
let loadPromise = null;

function getRedact() {
  if (instance !== null) return Promise.resolve(instance);
  if (loadPromise === null) {
    loadPromise = Redact.load().then(r => {
      instance = r;
      return r;
    });
    // On failure, clear the cached promise so a later request can retry
    // the load (e.g. after a transient network error during the first-use
    // weights download).
    loadPromise.catch(() => {
      loadPromise = null;
    });
  }
  return loadPromise;
}

function respond(obj) {
  process.stdout.write(JSON.stringify(obj) + "\n");
}

async function handleRequest(req) {
  if (req.type === "warmup") {
    await getRedact();
    respond({ type: "ready", id: req.id });
    return;
  }
  if (req.type === "detect") {
    const redact = await getRedact();
    const result = await redact.redaction(req.text, { labels: [...ALL_LABELS] });
    respond({
      type: "result",
      id: req.id,
      spans: result.items.map(item => ({
        original: item.original,
        type: item.label,
      })),
    });
    return;
  }
  respond({
    type: "error",
    id: req.id ?? null,
    message: `unknown request type: ${req.type}`,
  });
}

let lineBuf = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", chunk => {
  lineBuf += chunk;
  let idx;
  while ((idx = lineBuf.indexOf("\n")) !== -1) {
    const line = lineBuf.slice(0, idx);
    lineBuf = lineBuf.slice(idx + 1);
    if (line.trim() === "") continue;
    let req;
    try {
      req = JSON.parse(line);
    } catch {
      respond({ type: "error", id: null, message: "invalid JSON request" });
      continue;
    }
    handleRequest(req).catch(err => {
      respond({
        type: "error",
        id: req.id ?? null,
        message: String((err && err.message) || err),
      });
    });
  }
});
process.stdin.on("end", () => process.exit(0));
