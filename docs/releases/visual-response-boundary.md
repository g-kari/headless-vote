# Visual explanation feedback safety

The repository's Pi visual-explainer extension no longer converts messages from rendered HTML into agent messages or follow-up turns. Page scripts cannot prove that a person approved a response.

HTML output, browser/Glimpse opening, and session-end window cleanup remain available. Readers should copy feedback into the trusted chat interface. New generated pages use copy-only feedback rather than Send to agent. Re-rendered legacy pages are normalized to copy-only feedback. Previously generated files that are not re-rendered may still display their old button, but their responses are ignored by this extension.

This change does not sandbox model JavaScript or headless browser networking, and does not change the voting application or production configuration. Those boundaries require separate work.
