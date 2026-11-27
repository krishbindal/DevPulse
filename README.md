# DevPulse
A local-first, evidence-based GitHub repository intelligence prototype.

## Run
Requires Python 3.10+; no third-party packages for this milestone.

```sh
python -m devpulse.server
```
Open http://127.0.0.1:8000 and enter a public GitHub repository.

## Test
```sh
python -m unittest discover -s tests -v
```
Tests use mocked GitHub responses; they do not verify live API availability. The application makes unauthenticated requests to the official public GitHub API and may encounter rate limits. The open issue metric includes pull requests. Unknown analysis fields remain null instead of being guessed. The dashboard also requests GitHub's `/languages` endpoint; percentages use reported bytes, not line counts. A failed language request leaves metadata available and marks language data unavailable.

## Repository inventory and report export
The dashboard requests the default branch's recursive Git tree. It reports observed regular files, directories, symbolic links and submodules separately; it discovers dependency manifests, workflow definitions, documentation and test candidates using file names only. Truncated trees have lower-bound counts; examples are capped at 50 per category. No files are executed or cloned, no dependency versions or vulnerability findings are inferred. A failed inventory does not erase metadata. Download JSON to preserve raw results and source URLs. Metadata, languages and tree are separate requests, not a single atomic snapshot.

## CI evidence
The dashboard requests the latest public GitHub Actions run for the repository's default branch (one result, as returned by GitHub). It shows workflow name, status, conclusion, event, commit SHA, time and source. A successful run does not establish that every workflow passed or that the current branch head was tested. No runs is distinct from unavailable data. The overall CI health and test coverage fields remain unknown. GitHub may restrict Actions data or rate-limit unauthenticated scans.

## npm declaration evidence
If a regular root package.json is present in the tree, the scanner retrieves its immutable Git blob by SHA (up to 256 KB). It counts and lists up to 200 declarations across dependencies, devDependencies, optionalDependencies and peerDependencies. Non-version specifications are omitted from output; no package installation, execution, resolution, vulnerability scanning or monorepo enumeration occurs. A missing manifest in a truncated tree is unknown, not absent. Counts are declarations across sections, not unique or installed packages.

## Python requirement evidence
Reads a regular root requirements.txt by immutable Git blob SHA, within the same 256 KB limit. Recognizes a narrow subset: bare package names and simple exact pins (name==version). Unsupported lines, including ranges, markers, extras, URLs, includes, hashes and options, are counted without echoing their contents. No pip execution, include resolution, installed version inference or vulnerability claims. Partial status indicates unsupported lines or capped output (200 entries). Other Python manifest formats are not yet parsed.

## Optional OSV advisory lookup
The opt-in dashboard checkbox (or API query parameter advisories=1) sends only supported exact declared and locked package names, ecosystems and versions to https://api.osv.dev/v1/querybatch. It uses the documented batch API (https://google.github.io/osv.dev/post-v1-querybatch/) and reports returned advisory IDs for at most 50 unique simple numeric PyPI pins or exact npm major.minor.patch declarations and supported npm lockfile pairs. Duplicate queries are combined; results identify declaration and/or lockfile evidence. If capped, lockfile pairs are prioritized. It does not resolve ranges or verify installed dependencies. Lockfile records may include nested packages, but are not a verified dependency graph. Paginated results, caps, unsupported or ineligible declarations and unavailable/incomplete manifests are marked partial when some evidence can be reported. Per-ecosystem coverage identifies excluded observed declarations, unsupported lines and manifest availability. If neither source provides evidence, the lookup is unavailable, not a clean result. An empty response for a queried version is not proof of security. No repository URL, source code, credentials or manifest contents are sent. Live OSV connectivity remains to be verified; tests mock responses.

## npm lockfile evidence
Reads a regular root package-lock.json v2 or v3 by immutable blob SHA, limited to 1 MB. Recognizes standard numeric versions from node_modules package records, including nested locations; combines identical name/version pairs and reports occurrence counts. Root project, workspace-only paths, links, unsupported versions and invalid records are excluded or reported separately. Output is capped at 300 distinct pairs; no resolved URL, integrity string or raw source is displayed. This is lockfile metadata, not proof of installed packages, registry provenance or a complete dependency graph. Supported lockfile pairs are included in the optional OSV lookup, with explicit lockfile provenance and coverage limitations. Version 1 and alternative lockfiles remain unsupported.

## Local scan limits and cache
The loopback server allows at most two simultaneous upstream scans and eight new scan starts in a rolling 60-second window. Duplicate in-flight requests and exhausted capacity return HTTP 429 and Retry-After. Successful complete reports may be reused for 120 seconds, with at most 32 entries and 512 KiB per entry; incomplete/failed reports are not cached. Cache keys separate OSV opt-in from ordinary requests and normalize GitHub repository case. The X-DevPulse-Cache response header indicates HIT or MISS, and original scan timestamps are preserved. Limits are process-local and shared by all callers; they do not replace production ingress limits, authentication or a hardened server.

## Live API smoke verification
Run `python -m scripts.live_smoke` from the repository root. The separate Live API smoke GitHub Actions workflow uses fixed public fixtures to test a real unauthenticated GitHub metadata/language/tree scan and a real OSV lookup for a known historical lodash version. It never installs the fixture package or sends repository content. Network failures, rate limits, missing expected advisory evidence and unexpected responses cause a failing run rather than a synthetic success. The ordinary unit and HTTP tests remain deterministic and offline. Passing the smoke checks establishes only those exercised API paths at the run time, not full production readiness.

## Optional Python static review
Enable the dashboard checkbox or API parameter static=1. From the observed Git tree, up to five regular Python files of at most 64 KB each are selected lexicographically by path, retrieved by immutable blob SHA and parsed using Python's AST without executing the source. Four simple syntactic rules flag direct eval/exec calls, literal subprocess shell=True, direct pickle load/loads, and bare except clauses. Results show paths, line numbers, rule IDs and blob SHAs, not source excerpts. Alias tracking, taint analysis and exploitability verification are not supported; matches can be false positives, and absence of matches is not proof of safety. Excluded, failed and capped files are tracked, with at most 100 matches displayed. Static-enabled requests use a separate cache key.

## Engineering practice evidence
The dashboard evaluates eight indicators from observed tree and latest Actions metadata: README, license file, security policy, contribution guide, test candidates, workflow files, dependency manifests and latest workflow run. Recognized document locations are root, .github and docs; recognized names are exact common document names and extensions. Each indicator reports observed, not observed (within a complete returned tree or run response) or unknown, with up to five example paths. File presence is not evidence of content quality, successful CI, test coverage, valid licensing or security. No synthetic repository quality score is assigned. The JSON report includes the same checklist and source identifiers.

## Dashboard layout and assets
The dashboard groups evidence into overview, security, dependencies, engineering and inventory sections with keyboard-accessible anchor navigation, language meters and preserved report timestamps. CSS and JavaScript are served as fixed same-origin assets under a CSP that disallows inline script/style. The unit suite checks asset routes and markup targets; CI checks JavaScript syntax. Full browser and accessibility testing remain separate milestones.

## Scope
This is a local prototype, not a production server. Do not expose it publicly before implementing rate limiting, stronger server infrastructure and production security controls. No account tokens are accepted. The architecture deliberately avoids databases and frameworks until needed. See ROADMAP.md.
