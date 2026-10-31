# Changelog

Notable changes to this repository.

## 0.0.4 (TypeScript) and 0.0.3 (Python), 2026-10-31

Both packages. No change to the record, the pack or the verifier: a record
signed by 0.0.2 or 0.0.3 verifies unchanged.

- `remember` (and `build_record` / `buildRecord`) now validates `content`
  before it is hashed and signed, the way WitnessKit validates a payload:
  integers must be within the IEEE-754 safe range (2^53-1), nesting is capped
  at 64 levels, and a non-JSON type is refused with a clear error instead of a
  `RecursionError` or a content id that differs between the two languages.
  Tests in both suites.
- Python `__version__` matches `pyproject.toml` (it had stayed at 0.0.1).
- Shared Ed25519 reference file: the docstring is generic (the same bytes
  serve all four signing kits); CI pins the SHA-256 of `ed25519.py`,
  `canonical.py` and `canonical.ts`.
- `python/LICENSE` is in the package directory, so sdists and wheels carry it.
- Repository: CI runs every file under `python/tests` through pytest, installs
  with `npm ci`, pins every action to a commit SHA, declares read-only
  permissions and pins the Semgrep image; Dependabot for npm, pip and Actions;
  a tag-driven Release workflow with Trusted Publishing; SECURITY.md points to
  private vulnerability reporting; CITATION.cff carries the version.

## 0.0.3 (2026-10-07)

TypeScript package only; no change to the record, the pack or the verifier.

- `npm test` now passes `--experimental-strip-types`, so it works on Node 22.6
  to 22.17 as the README promised (type stripping is unflagged only from
  22.18).
- The module's exported `__version__` now matches `package.json` (it had
  stayed at 0.0.1 through the 0.0.2 release).
- README: the Node version note.

## 2026-09-08

- README: added "The accountability stack, September 2026" positioning section
  linking the suite to the MM Control Stack Compact.
