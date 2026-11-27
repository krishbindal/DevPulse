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

## Scope
This is a local prototype, not a production server. Do not expose it publicly before implementing rate limiting, stronger server infrastructure and production security controls. No account tokens are accepted. The architecture deliberately avoids databases and frameworks until needed. See ROADMAP.md.
