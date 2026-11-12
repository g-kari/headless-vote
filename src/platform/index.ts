import type { Env } from "../types";
import { localAuthProvider } from "./auth-local";
import { oidcAuthProvider } from "./auth-oidc";
import { createAnalyticsStore } from "./analytics-store";
import { createEmailSender } from "./email";
import { createObjectStore } from "./objects";
import type { AuthProvider, Platform } from "./ports";
import { createRateLimitStore } from "./ratelimit";
import { createWebhookTransport } from "./webhook-transport";

export function selectAuthProvider(name: string | undefined): AuthProvider {
  const id = (name || "oidc").toLowerCase();
  if (id === "oidc") return oidcAuthProvider;
  if (id === "local") return localAuthProvider;
  throw new Error(`Unknown AUTH_PROVIDER "${id}". Use "oidc" or "local".`);
}

export function createPlatform(env: Env): Platform {
  return {
    auth: selectAuthProvider(env.AUTH_PROVIDER),
    email: createEmailSender(env),
    objects: createObjectStore(env),
    rateLimits: createRateLimitStore(env),
    webhooks: createWebhookTransport(env),
    analytics: createAnalyticsStore(env),
  };
}

export type { Platform } from "./ports";
