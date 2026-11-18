# Model script sandbox

A `<ve-flow>` model is JavaScript from a page, and the kit's machine walker used
to run it in a child Node process with the host's full privileges: filesystem,
environment, child processes, and the network. The walker now confines that
child in two layers.

The first layer is the Node permission model (`--permission`, spelled
`--experimental-permission` on Node 22). The child may read only the
repository root it walks and the kit's own directory — the model and the
repository modules it imports live under those two — and gets no filesystem
writes, no child processes, no worker threads, and no native addons. Its
environment is empty, so host variables never reach the model.

The permission model does not govern the network, so a preload
(`kit/model-guard.mjs`) is the second layer: it makes the `net`, `tls`,
`http`, `https`, `dns`, `dgram`, `http2`, and `inspector` modules throw on
import, replaces global `fetch` with a stub that rejects, and removes
`WebSocket`. A model that reaches for any of these fails its walk with the
denial named in the error, in the same shape as any other model error.

On a Node without the permission model the walker refuses to run the model
rather than running it unconfined; the error names the missing flag.

Validation: `scripts/visual-explainer-model-sandbox-security.mjs` (part of
`npm run test:security:node`) walks a benign model that imports repository
code, and probes each boundary from inside a model — file write, read outside
the root, child process, worker thread, environment leak, and a fetch to a
listening local server that must receive no request. Locally verified on
Node 24 (benign walk completes; escape probes denied); CI on Node 22 covers
the `--experimental-permission` spelling.

This change confines executable model JavaScript only. It does not change how
rendered HTML is opened or what network access rendered pages get, and makes
no application deployment or authentication changes.
