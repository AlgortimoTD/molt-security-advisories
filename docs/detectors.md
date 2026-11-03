# Detectors

A detector is a machine-checkable rule that tells a consumer whether its own environment is
affected. Consumers such as the `runtime-security-check` skill evaluate detectors locally and
never send inventory anywhere. A consumer that does not implement a detector type reports the
advisory as a manual check and shows its `remediation` and `verification` text.

Every detector has `type`, `params` and an optional `context`:

- `browsing`: the component processes untrusted content (agent browsers, scrapers, mail).
- `test-only`: the component is normally used only against the owner's own application (for
  example a pinned test browser). Consumers report it without failing a strict gate.
- `any`: no distinction.

## Types (version 1)

**`chromium-browser-version`**
Chromium-family executables (system Chrome, Chromium, Chrome for Testing, Playwright browser
caches, tool-managed browsers). Version is read from the executable's `--version` output, never
from a directory name.
Params: `product` (`chrome` for Google Chrome and Chrome for Testing), `fixed` (first fixed
version). Affected when the version is lower than `fixed`.

**`running-process-flag`**
A running process of a family started with a flag.
Params: `family` (`chromium`), `flag` (for example `--no-sandbox`).
Consumers report the executable and version, never the other arguments.

**`executable-version`**
A command-line tool or runtime found on the machine.
Params: `executable` (for example `node`, `git`), `ranges` (list of `{introduced, fixed}`;
`introduced` optional; affected when introduced <= version < fixed).

**`package-version`**
A package installed in a project lockfile or globally.
Params: `ecosystem` (`npm`, `PyPI`, `Go`, `crates.io`), `name`, `ranges` (as above).

**`manual`**
Anything a rule cannot express yet.
Params: `instructions`, a short check a person or agent can run.

New detector types are added here first, then implemented in consumers, and only then used in
advisories.
