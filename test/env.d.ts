import type { Env as AppEnv } from "../src/types";

declare global {
  namespace Cloudflare {
    // Make `env` from "cloudflare:test" carry this app's bindings.
    interface Env extends AppEnv {}
  }
}

export {};
