// Model sandbox regression: a <ve-flow> model runs in a confined child process.
// A benign model that imports repo code must still walk; a model that reaches for the
// host — filesystem writes, reads outside the repo, child processes, workers, the
// network, the host's environment — must get nothing. No browser or agent is launched.
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";

const { loadModel } = await import("../.claude/skills/visual-explainer/kit/machine.mjs");

const dir = mkdtempSync(join(tmpdir(), "ve-sandbox-test-"));
const root = join(dir, "root");
const outside = join(dir, "outside.txt");
mkdirSync(root, { recursive: true });
writeFileSync(join(root, "step.mjs"), "export const bump = (s) => (s.n < 2 ? { n: s.n + 1 } : s);\n");
writeFileSync(outside, "sentinel outside the root\n");
process.env.VE_SANDBOX_MARKER = "host-only-value";

const outcomeOf = (r) => {
  assert.deepEqual(r.errors, [], `model must run cleanly, got: ${r.errors}`);
  return JSON.parse(r.walk.states[0]);
};
// Each probe reports through its state, so one denial cannot mask another.
const probe = (body) => `
import { bump } from "./step.mjs";
${body}
events = { stay: (s) => s };
state = (s) => JSON.stringify(s);
`;

try {
  // A model that imports repo code and walks still works, sandboxed.
  const benign = loadModel({
    root,
    text: `
import { bump } from "./step.mjs";
init = { n: 0 };
events = { bump };
state = (s) => (s.n === 0 ? "start" : "moved");
`,
  });
  assert.deepEqual(benign.errors, []);
  assert.deepEqual(benign.walk.states, ["start", "moved"]);

  // Filesystem write outside (and inside) the sandbox's read-only world: denied, and no file appears.
  const target = join(dir, "escaped.txt");
  const write = loadModel({
    root,
    text: probe(`
const { writeFileSync } = await import("node:fs");
let write = "allowed";
try { writeFileSync(${JSON.stringify(target)}, "x"); } catch { write = "denied"; }
init = { write };
`),
  });
  assert.equal(outcomeOf(write).write, "denied");
  assert.equal(existsSync(target), false, "the model must not create files");

  // Reading a file outside the repo root: denied, even though it exists.
  const read = loadModel({
    root,
    text: probe(`
const { readFileSync } = await import("node:fs");
let read = "allowed";
try { readFileSync(${JSON.stringify(outside)}, "utf8"); } catch { read = "denied"; }
init = { read };
`),
  });
  assert.equal(outcomeOf(read).read, "denied");

  // Child processes: denied.
  const spawn = loadModel({
    root,
    text: probe(`
let spawn = "allowed";
try {
  const { spawnSync } = await import("node:child_process");
  const r = spawnSync("echo", ["hi"]);
  if (r.error) spawn = "denied";
} catch { spawn = "denied"; }
init = { spawn };
`),
  });
  assert.equal(outcomeOf(spawn).spawn, "denied");

  // Worker threads: denied.
  const worker = loadModel({
    root,
    text: probe(`
let worker = "allowed";
try {
  const { Worker } = await import("node:worker_threads");
  const w = new Worker("0", { eval: true });
  w.terminate();
} catch { worker = "denied"; }
init = { worker };
`),
  });
  assert.equal(outcomeOf(worker).worker, "denied");

  // The host's environment does not leak into the sandbox.
  const env = loadModel({
    root,
    text: probe(`init = { env: process.env.VE_SANDBOX_MARKER ? "leaked" : "absent" };`),
  });
  assert.equal(outcomeOf(env).env, "absent");

  // The network is off: a fetch to a listening local server never arrives.
  let hits = 0;
  const server = createServer(() => { hits++; });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try {
    const net = loadModel({
      root,
      text: probe(`
let fetch = "allowed";
try { await fetch("http://127.0.0.1:${server.address().port}/"); } catch { fetch = "denied"; }
init = { fetch };
`),
    });
    assert.equal(outcomeOf(net).fetch, "denied");
    assert.equal(hits, 0, "no request may reach the server");
  } finally {
    server.close();
  }

  console.log("PASS model sandbox: repo imports walk; write/read-outside/spawn/worker/env/network all denied");
} finally {
  delete process.env.VE_SANDBOX_MARKER;
  rmSync(dir, { recursive: true, force: true });
}
