# Contributing

Thanks for looking at headless-vote. Issues and small, tested changes are welcome.

## Before you open a change

- Run `npm test` and `npm run typecheck`.
- Do not commit secrets, production hostnames, client secrets, or real `SESSION_SECRET` values. Put examples in `config/example.env`.
- Keep product rules (votes, questions, roles, quotas) independent of a specific auth or mail vendor. New host integrations belong behind the interfaces in `src/platform`. See `docs/adapters.md`.
- Preserve the existing security checks: same-origin mutations, hashed API keys, no voter tokens in exports or webhooks, and exact CORS matches.

## License

This repository does not currently include a `LICENSE` file. Choosing a license (for example Apache-2.0 or MIT) is a decision for the repository owner. This document does not grant a license. Do not assume you can redistribute the code until the owner adds one.
