<p align="center"><img src="assets/molt-logo.png" alt="MOLT" width="205"></p>

# MOLT Security Advisories

Verified security advisories for the tools that AI agents and developers run every day:
browsers driven by agents, coding assistants, runtimes, package managers and their plugins.

Security news travels fast and much of it is wrong. Every advisory here starts from a lead
(a post, an article, a vendor feed) and is published only after the facts are checked against
primary sources: the vendor's own advisory or release notes, the CVE record, NVD, and CISA's
catalog of exploited vulnerabilities. Claims that turn out false or exaggerated are recorded
too, so nobody has to chase them again.

## What is in each advisory

- **What is affected**, with fixed versions taken from the vendor.
- **Severity for agent environments**: our own level and how soon to act (24 hours to next
  update), with the reasoning. The vendor's rating is kept next to it.
- **Who is exposed**: the conditions that make it matter, for example a browser that an agent
  drives to pages you do not control.
- **Detectors** a tool can evaluate on its own machine to tell whether it is affected.
- **Remediation** with the risk of each change, and **verification** steps that prove the fix
  works.
- **Sources**, each tagged with the fields it backs, and the review by a second model.

Records never describe anyone's machines. They describe products and conditions; you check your
own environment.

## Use it

The whole feed is one file:

```
https://raw.githubusercontent.com/AlgortimoTD/molt-security-advisories/main/feed.json
```

`advisories` holds every advisory in full (schema [`msa/1`](schema/advisory.schema.json)) and
`rejected` lists the claims we checked and found false, misleading, exaggerated or
unverifiable. The MOLT `runtime-security-check` skill reads this feed, evaluates the detectors
locally and offers the fixes.

| Folder | Content |
| --- | --- |
| `advisories/YYYY/` | Published and withdrawn advisories, one JSON file each |
| `rejected/YYYY/` | Claims that did not hold up, with the sources that contradict them |
| `schema/` | JSON Schemas for both record types |
| `docs/` | [Evidence policy](docs/evidence-policy.md), [severity rubric](docs/severity-rubric.md), [detectors](docs/detectors.md) |

## How a record is published

1. A lead is found by the daily scout or reported by a person.
2. The author reads the primary sources directly and writes the record.
3. A different model re-reads every source and approves the record or sends it back.
4. `npm run check` validates the schema, the evidence tiers, the review and the feed.
5. The pull request merges only with every check green.

Corrections are added to the record's history; published records are never deleted.

## Report or correct

Open an issue with the primary source that supports the change. Please report vulnerabilities in
a product to its vendor, not here.

## License

Advisory records and documentation: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
Scripts: MIT. Both in [LICENSE](LICENSE).

---

Published by [MOLT](https://molt.solutions/). Smart Tech, Real Impact.
