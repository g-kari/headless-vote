import { verifyJwt } from "../oidc";
import { unauthorized } from "../errors";
import type { Env } from "../types";
import type { AuthIdentity, AuthProvider } from "./ports";

/** Generic OpenID Connect adapter. The issuer, client id, and label come from configuration. */
export const oidcAuthProvider: AuthProvider = {
  id: "oidc",
  label(env) {
    return env.AUTH_LABEL?.trim() || "OpenID Connect";
  },
  capabilities: { localPasswords: false, emailVerification: false },
  async verifyAccessToken(env: Env, token: string): Promise<AuthIdentity> {
    if (!env.OIDC_CLIENT_ID) {
      throw unauthorized("INVALID_TOKEN", "Presented login token is not valid");
    }
    try {
      const verified = await verifyJwt(env, token, { audience: env.OIDC_CLIENT_ID });
      return {
        sub: verified.sub,
        email: typeof verified.claims["email"] === "string" ? verified.claims["email"] : undefined,
        name: typeof verified.claims["name"] === "string" ? verified.claims["name"] : undefined,
      };
    } catch {
      throw unauthorized("INVALID_TOKEN", "Presented login token is not valid");
    }
  },
};
