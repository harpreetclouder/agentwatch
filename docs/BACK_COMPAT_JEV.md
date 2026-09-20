# Backward compatibility: historical `jev` strings

Product brand is **VEYRA** (`veyra`, `@veyra/*`, `.veyra`). Any remaining `jev` / `Jev` / `.jev` in this repo is **intentional**, not an unfinished rename.

| Kind | What | Why kept |
|------|------|----------|
| External model slug | `~typesafe/jev-latest`, `TypesafeJev*`, provider alias `jev` | OpenRouter/TypeSafe **Jev** LLM Decisions API ID — **unrelated to the VEYRA product rename**; changing the slug would break the API |
| Legacy plane path | `.jev` segment in policy-engine + `.gitignore` `.jev/` | Protect leftover dirs after JEV→VEYRA rebrand; **active plane is `.veyra` only** |
| Backup junk pattern | `*.jev-backup*` (gitignored) | Historical Claude settings backups from rebrand tooling — not fixtures |
| Checkout directory | local path `…/jev` (e.g. `/Users/macbook/jev`) | Filesystem folder name of this clone; **do not rename**; not product branding |

No `@jev/*` packages or imports. Do not treat TypeSafe “Jev” as the product name.
