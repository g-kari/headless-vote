// Loaded into the model child (machine.mjs) with --import, before any model code runs.
// The Node permission model confines the child's filesystem, processes, workers, and
// addons, but it does not govern the network, so this turns the network primitives off:
// a model walks states; it has no reason to reach a socket. Imported repo code runs in
// this same thread, so the stubs apply to it too. This is a second layer over the
// permission flags, not a replacement for them: code that rebuilds a primitive from
// lower-level pieces is stopped by the permission model (no addons, no workers, no
// child processes), not by these stubs.
import net from "node:net";
import tls from "node:tls";
import http from "node:http";
import https from "node:https";
import dns from "node:dns";

const fail = (what) => new Error(`network access is off in the model sandbox (${what})`);
const deny = (what) => () => { throw fail(what); };

net.Socket.prototype.connect = deny("net");
net.connect = deny("net");
net.createConnection = deny("net");
tls.connect = deny("tls");
http.request = deny("http");
http.get = deny("http");
https.request = deny("https");
https.get = deny("https");
for (const fn of ["lookup", "resolve", "resolve4", "resolve6", "resolveAny", "lookupService"]) {
  if (typeof dns[fn] === "function") dns[fn] = (...args) => { const cb = args.find((a) => typeof a === "function"); if (cb) cb(fail("dns")); };
}
if (dns.promises) for (const fn of ["lookup", "resolve", "resolve4", "resolve6", "resolveAny", "lookupService"]) {
  if (typeof dns.promises[fn] === "function") dns.promises[fn] = () => Promise.reject(fail("dns"));
}
globalThis.fetch = () => Promise.reject(fail("fetch"));
globalThis.WebSocket = class {
  constructor() { throw fail("WebSocket"); }
};
