import { pathToFileURL } from "node:url";

// Never put a rendered file path through cmd.exe: even argument arrays are parsed
// by `cmd /c start`. FileProtocolHandler receives one file URL as data instead.
// Keep this helper shared by both hosts and both standalone renderers.
export function windowsBrowserCommand(path) {
  return ["rundll32.exe", ["url.dll,FileProtocolHandler", pathToFileURL(path, { windows: true }).href]];
}
