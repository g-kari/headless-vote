# Windows rendered-page opening

The Visual Explainer Pi extension, MCP host, and both standalone renderers now
open Windows output files through `rundll32.exe url.dll,FileProtocolHandler`,
passing one file URL as data, without invoking `cmd /c start`. Paths containing
ampersands, environment-variable-like strings, spaces, or Unicode no longer
enter a command-shell parser. All four callers share the argument builder.

The existing macOS/Linux opener commands, output naming, explicit open options,
Glimpse selection/fallback, and host error reporting remain unchanged. No output
extension restrictions or new runtime dependencies were added.

Validation includes mocked Windows dispatch for all four callers, file-URL
roundtrips for drive and UNC paths, and macOS/Linux dispatch controls. The
pre-change source fails the boundary regression. No Windows OS, real registered
browser/file association, UNC access, or `FileProtocolHandler` integration has
been exercised in the cloud Linux environment. This is a reviewed repair
candidate, not completed real-Windows verification; do not mark the finding
fully verified or merge solely from the Linux CI result.

This change does not sandbox executable model JavaScript or HTML network access
and makes no application deployment or authentication changes.
