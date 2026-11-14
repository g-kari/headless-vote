// Mock the OS boundary; never launch a browser, cmd, or rundll32 on the test host.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { windowsBrowserCommand } from '../.claude/skills/visual-explainer/kit/browser-opener.mjs';
const base = new URL('../.claude/skills/visual-explainer/', import.meta.url);
const paths = [
  String.raw`C:\reports\a&calc&b.html`,
  String.raw`C:\reports\%COMSPEC% ^ & ! (test).html`,
  String.raw`C:\日本語 フォルダ\100% #report.html`,
  String.raw`\\server\share\report & notes.html`,
  String.raw`C:\reports\ordinary.html`,
  String.raw`C:\reports\custom-output.txt`,
  String.raw`C:\reports\%26%COMSPEC%,semi;quote'😀.html`,
];
for (const path of paths) {
  const [command, args] = windowsBrowserCommand(path);
  assert.equal(command, 'rundll32.exe');
  assert.equal(args[0], 'url.dll,FileProtocolHandler');
  assert.equal(args.length, 2);
  assert.equal(fileURLToPath(args[1], { windows: true }), path);
  assert.equal(new URL(args[1]).protocol, 'file:');
  assert.equal(new URL(args[1]).hash, '');
}
// Execute the actual thin dispatch functions from each entry point with mocked
// process/spawn. This avoids loading MCP dependencies or executing renderer CLI
// code, while ensuring all four live callers use the shared boundary.
for (const rel of ['extension.ts', 'mcp/server.mjs', 'kit/render.mjs', 'plan/render.mjs']) {
  const source = readFileSync(new URL(rel, base), 'utf8');
  const host = rel === 'extension.ts' || rel === 'mcp/server.mjs';
  const name = host ? 'openInBrowser' : 'openFile';
  let fn = source.match(new RegExp(`(?:async )?function ${name}\\([^]*?\\n\\}`))?.[0];
  assert.ok(fn, `dispatch function exists: ${rel}`);
  if (rel.endsWith('.ts')) fn = fn.replace('path: string', 'path').replace(': Promise<OpenResult>', '');
  assert.match(source, /import \{ windowsBrowserCommand \} from /);
  if (host) assert.match(source, /spawn\(command, args, \{[^}]*shell: false/);
  for (const platform of ['win32', 'darwin', 'linux']) {
    for (const path of paths) {
      const calls = [];
      let unrefs = 0;
      const context = vm.createContext({
        process: { platform }, windowsBrowserCommand,
        runOpener: async (command, args, target) => {
          calls.push({ command, args, target });
          return { openAttempted: true, openStatus: 'dispatched', openTarget: target };
        },
        spawn: (command, args, options) => {
          calls.push({ command, args, options });
          return { unref: () => unrefs++ };
        },
      });
      const dispatch = vm.runInContext(`(${fn})`, context);
      const result = await dispatch(path);
      assert.equal(calls.length, 1, rel);
      const call = calls[0];
      assert.notEqual(call.command, 'cmd');
      if (platform === 'win32') {
        assert.equal(call.command, 'rundll32.exe', rel);
        assert.deepEqual(Array.from(call.args), windowsBrowserCommand(path)[1]);
      } else {
        assert.equal(call.command, platform === 'darwin' ? 'open' : 'xdg-open');
        assert.deepEqual(Array.from(call.args), [path]);
      }
      if (host) {
        assert.equal(result.openStatus, 'dispatched');
        assert.equal(call.target, 'browser');
      } else {
        assert.equal(call.options.shell, false);
        assert.equal(call.options.detached, true);
        assert.equal(call.options.stdio, 'ignore');
        assert.equal(unrefs, 1);
      }
    }
  }
}
console.log('PASS four browser opener boundaries: no cmd, literal file URLs, existing Unix dispatch preserved (Windows OS mocked)');
