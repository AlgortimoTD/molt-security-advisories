# Daily security scout

A deterministic Node 22+ ESM supervisor collects leads, invokes a Codex author and an
independent Claude reviewer only when there is work, and publishes approved records
through a checked pull request. No npm dependencies are required. The repository's
evidence policy, severity rubric and detector contract remain authoritative.

Nothing in this directory installs a timer, registers an agent, selects an account,
changes credentials or grants publication authority. Before activation, the operator
must register the scheduled agent with its private runLedger in the host panel, verify
its configured profiles and exact models, check live account capacity under the host's
delegation policy, and approve the runtime launch specification. Use a non-Fable Claude
model unless the owner explicitly authorizes Fable for this agent. No real model or
publishing operation is part of the offline tests.

## Flow and failure boundaries

1. `run.mjs` validates its private config and takes the host `acquireLock` flock on
   `stateDir/scout.lock`. A second run writes a skipped ledger event and exits 75.
2. Require a clean canonical checkout and a GitHub SSH push remote. Fetch main and create
   a fresh worktree from the remote's main revision on `scout/YYYY-MM-DD`, using Bogotá's
   calendar date. Existing local or remote branches get `-2`, `-3`, and so on.
3. `collect.mjs` fetches official Chrome desktop stable/extended updates, CISA KEV,
   reviewed high/critical GitHub advisories for npm/pip/go/actions, Node vulnerability
   notices, developer-relevant Ubuntu USNs, and security-related releases for the six
   configured agent/developer tooling repositories. Each source has its own 20-second
   deadline and error boundary. GitHub pagination is followed until it crosses the
   cursor window, with a 100-page safety limit. `GITHUB_TOKEN` is optional and used only
   in the GitHub API request header, never logged or forwarded to other feed hosts.
4. `read-x.mjs` opens the configured qa-browser profile with text capture, navigates to
   Following and live searches, reads and scrolls, and stops the browser in `finally`.
   Only the exact Following tab can be clicked. There is no generic click, typing,
   form submission or arbitrary JavaScript action. Login, missing profiles and busy
   profiles make X unavailable while official collection continues. Three consecutive
   login walls produce one blocker notice; recovery resets the counter. A failed stop
   is a blocker because the profile lease may still be held. Defaults are 60 timeline
   posts and 20 per search, each with URL, handle, time and at most 600 characters.
5. Write official items, source errors and untrusted X posts to the private run's
   `leads.json`. If neither source contributes any leads, finish without inference,
   remove the worktree, acknowledge the cursor and record `modelInvoked:false`.
   All official sources failing is a failed run, not a quiet day.
6. Run the author through the configured host `scripts/agent-run.mjs`, with the
   workspace-write sandbox and network enabled. The author may write only record JSON.
   Require a complete result marker and a successful observed invocation in the host
   ledger. Restore out-of-scope changes, including staged files, deleted published
   records, symlinks and untracked files. Record reverted paths privately. Refuse a
   model that changes HEAD. Validate the records, tolerating only the existing
   validator's two explicit pending review errors. Existing records need appended
   history and preserved identity and publication dates.
7. Send the exact diff and complete candidate JSON to Claude. Supply the exact
   `--allowedTools` string from the brief, an additional restricted tool inventory,
   `dontAsk` permission mode, and `--strict-mcp-config` with zero servers. A reviewer
   that modifies the worktree fails the run. Require complete coverage, a different
   exact model, and no open findings for approval. There is at most one author fix
   round followed by one re-review of every remaining changed record. Restore existing
   records or remove new records that still lack approval. These are withheld drafts,
   distinct from evidence-backed rejected claims in `rejected/`.
8. Fill review metadata deterministically only after approval. Runtime-observed model
   names win; the declared exact name must agree if an observation is available.
   Run `npm run feed`, then the full `npm run check`, and commit only approved records
   and the generated feed.
9. Unless dry-run, push the task branch over SSH, create a PR using a private body file,
   and poll checks every 30 seconds for at most 15 minutes. All checks must have actual
   success, the head must be unchanged, and mergeability must be clean. Empty, skipped,
   neutral, unknown, failed or blocked checks do not permit merging. Merge using squash,
   delete-branch and a matching head guard. No admin override, force push or main push.
   Confirm GitHub reports the PR merged before any publication notices.
10. Notify risks for newly published high/critical advisories with the public record
    link. Notify a daily info summary only for publications or withheld records.
    Authentication failures, merge blocks and persistent X sign-out need a person.
    Quiet days send no notice. Every notice uses `agent-approval notify` and a stable
    `molt-security-scout:<id>` key; delivery failure fails the run without cursor ack.
11. Remove the exact temporary worktree, acknowledge the cursor atomically, and write
    the final `agent-run/1` row. A failure leaves the cursor unchanged. Private run
    evidence includes leads, prompts, structured results, the guard report and any
    uncommitted candidate records retained during failure cleanup. No prompt or
    response text enters the ledger. Stderr has bounded step messages and never raw
    command output or credentials.

`collect.mjs` can run alone, producing `{items,sourceErrors,nextCursor}` on stdout without
changing state. Normalized items have `{source,id,title,url,published,summary}` with
summaries limited to 500 characters. First collection uses three days. Afterward, a
one-day overlap plus seen IDs handles date-only KEV additions and delayed entries.
Each successful source advances independently in the proposed cursor; failed sources
retain their old entry. Only the orchestrator acknowledges the complete run. This is
at-least-once processing: a failure after a merge can revisit leads, and authors must
check existing records rather than duplicate them.

Both model prompts emit the same result twice, as `SCOUT_RESULT={json}` for the current
host runner's outcome parser and as `SCOUT_RESULT {json}` for the requested interface
(or `REVIEW_RESULT` respectively). Conflicting values, missing markers, incomplete
coverage, incomplete runtime rows and invalid JSON fail closed.

## Configuration

Run `node scout/run.mjs --config /absolute/private/config.json`. The default is
`$XDG_CONFIG_HOME/molt-security-scout/config.json`, falling back to
`~/.config/molt-security-scout/config.json`. The file must be owned by the current user,
regular, not a symlink, and mode 600. State directories are mode 700 and files mode 600.
Paths must be absolute. No credentials belong in this config.

The configuration contract is:

| Field | Type and constraint |
| --- | --- |
| `repo` | Absolute path to the clean canonical repository |
| `worktreesDir` | Absolute parent of temporary worktrees |
| `stateDir` | Optional absolute private state path; default `$XDG_STATE_HOME/molt-security-scout` or `~/.local/state/molt-security-scout` |
| `ledgerPath` | Absolute `.jsonl` runLedger registered with the panel |
| `llmControlPanelPath` | Optional host panel checkout; default `~/molt/llm-control-panel` |
| `qaBrowser` | Optional qa-browser executable; defaults to that panel checkout's skill executable |
| `x.enabled` | Boolean |
| `x.profile` | Authorized named profile, required when enabled |
| `x.searches` | Array of live-search query strings, each at most 1000 characters |
| `x.timelineMax`, `x.searchMax` | Optional integers 1 to 500; defaults 60 and 20 |
| `x.headed` | Optional boolean to require a visible browser |
| `author.provider` | Exactly `codex` |
| `reviewer.provider` | Exactly `claude` |
| `author.profile`, `reviewer.profile` | Absolute provider profile paths |
| `author.model`, `reviewer.model` | Explicit model identifiers, different from each other |
| `author.timeoutS`, `reviewer.timeoutS` | Integer seconds, 1 to 3000 per invocation; combined four-run deadlines at most 9000 seconds |
| `github.remote` | Named Git remote with a `git@github.com:OWNER/REPO.git` push URL |
| `github.base` | Exactly `main` |
| `notify.agent` | Registered agent identifier; up to 54 lowercase letters, digits or hyphens |
| `notify.project` | Project or repository routing name |
| `dryRun` | Required boolean |

Example with fictional placeholders. Replace paths and model/profile placeholders with
reviewed installed values. Do not infer an account from the Git remote.

```json
{
  "repo": "/srv/example/security-feed",
  "worktreesDir": "/srv/example/security-worktrees",
  "stateDir": "/srv/example/private/security-scout-dry-run",
  "ledgerPath": "/srv/example/private/security-scout-dry-run/runs.jsonl",
  "llmControlPanelPath": "/srv/example/control-panel",
  "x": {
    "enabled": false,
    "profile": "authorized-security-reading-profile",
    "searches": ["CVE coding assistant", "browser security update"],
    "timelineMax": 60,
    "searchMax": 20
  },
  "author": {
    "provider": "codex",
    "profile": "/srv/example/private/codex-profile",
    "model": "AUTHOR_EXACT_MODEL",
    "timeoutS": 1800
  },
  "reviewer": {
    "provider": "claude",
    "profile": "/srv/example/private/claude-profile",
    "model": "REVIEWER_EXACT_MODEL",
    "timeoutS": 1800
  },
  "github": { "remote": "origin", "base": "main" },
  "notify": { "agent": "security-scout", "project": "example-security-feed" },
  "dryRun": true
}
```

Dry-run still performs collection, real author/reviewer inference, local gates and a
local commit. It skips push, PR, merge and all notices, printing the planned actions.
The worktree is removed but its local branch and commit remain for inspection. Dry-run
also acknowledges its cursor, so always use a separate state directory and ledger from
production to avoid consuming unpublished leads. It is not an offline or free mode.

Exit codes: 0 for completed work, 75 for a busy lock, 1 for every other failure.
Auth and merge failures need operator review, not an automatic provider/account switch.
The script never changes profiles or falls back to another model.

## Timer templates, not installed

The service's explicit Node and script paths must point at the registered host runtime.
Provider and qa-browser executables must already be provisioned on its PATH. Its profile,
ledger, permissions and MCP policy must be registered and reviewed before activation.
The suggested 1800-second model timeouts leave time for checks and cleanup within the
three-hour service bound. Keep four model deadlines, grace periods and the 15-minute PR wait within
three hours when choosing timeouts.

`molt-security-scout.service`:

```ini
[Unit]
Description=Daily verified security advisory scout
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
WorkingDirectory=/srv/example/security-feed
Environment=PATH=/srv/example/bin:/usr/local/bin:/usr/bin:/bin
ExecStart=/srv/example/bin/node /srv/example/security-feed/scout/run.mjs --config /srv/example/private/security-scout/config.json
UMask=0077
SuccessExitStatus=75
TimeoutStartSec=3h
Nice=10
KillMode=control-group
```

`molt-security-scout.timer`:

```ini
[Unit]
Description=Read security leads daily at 07:00 Bogotá time

[Timer]
OnCalendar=*-*-* 07:00:00 America/Bogota
Persistent=true
Unit=molt-security-scout.service

[Install]
WantedBy=timers.target
```

## Verification

`npm test` already discovers `test/scout.test.mjs` through the existing wildcard.
`npm run check` runs these offline tests, the record validator and the deterministic
feed check. Fixture snippets cover Atom, RSS, KEV and GitHub advisory JSON. Tests also
exercise cursor isolation, read-only browser step construction and cleanup, diff
restoration, review metadata, strict markers, the full model-free path, bounded fix
rounds, local dry-run commits, lock contention, failure cleanup and merge gates.
Provider outputs, network and GitHub publication are simulated; actual git operations
use disposable local repositories. No real model, profile or external write is used.

Before enabling publication, the supervisor still needs a registered, owner-approved
runtime, a real profile/tool capability probe, live source reads, and a controlled
end-to-end PR with the repository's actual required checks. CI branch rules, provider
credentials, browser login and network availability cannot be proven by offline tests.
Private run evidence and retained local branches need the host's normal retention
policy; the scout removes its temporary worktrees but never prunes shared state.
