# Severity rubric

Molt severity answers one question: how urgently should an environment that runs AI agents,
developer tools and small servers act on this? It is set by the author, checked by the reviewer
and kept separate from the vendor's rating (`vendor_severity`), which is recorded as published.

## Factors

1. **Reach.** Can it be triggered remotely, for example by a web page, a message, a package or a
   file an agent processes, or does it need local access?
2. **Preconditions.** Authentication, user interaction (an agent opening a page counts as
   interaction that happens without a person), a non-default configuration.
3. **Impact.** Code execution or sandbox escape, credential or data exposure, integrity of the
   supply chain, denial of service.
4. **Exploitation.** Listed in CISA KEV or confirmed exploited by the vendor; public exploit;
   none known.
5. **Agent exposure.** Agents act unattended and with the owner's credentials. A flaw reachable
   from content an agent reads (web pages, repositories, documents, packages) weighs more than
   the vendor's desktop-user model suggests.

## Levels

- **critical**: remote code execution or sandbox escape reachable from content an agent can
  process, with no meaningful precondition; or anything confirmed exploited in the wild that
  reaches credentials or code execution. Act within 24 hours.
- **high**: remote code execution with a precondition commonly met in agent environments (for
  example a browser running without its sandbox), credential exposure, or a supply chain
  compromise of a widely used package. Act within 72 hours.
- **medium**: needs local access or an uncommon configuration, or limits impact to one service
  or a denial of service. Act within 30 days.
- **low**: hardening, defense in depth, or impact only under unusual conditions. Next regular
  update.
- **informational**: no vulnerability, but guidance worth knowing (for example a default that
  is unsafe for agents).

Raise one level when CISA KEV or the vendor confirms exploitation. Lower one level when the
affected component is commonly used only in a context that removes the reach (for example a
test-only build used solely against your own application), and say so in the rationale.

## What the advisory records

- `severity.level`: one of the levels above.
- `severity.urgency`: `24h`, `72h`, `30d` or `next-update`.
- `severity.rationale`: two or three sentences naming the factors that decided the level.
- Conditional exposure goes in `exposure`. When the same flaw has different urgency by context
  (a browser used by agents on the open web versus a pinned test build against your own app),
  the advisory states the level for the worst common case and explains the others in `exposure`.
