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
Tests use mocked GitHub responses; they do not verify live API availability. The application makes unauthenticated requests to the official public GitHub API and may encounter rate limits. The open issue metric includes pull requests. Unknown analysis fields remain null instead of being guessed.

## Scope
This is a local prototype, not a production server. Do not expose it publicly before implementing rate limiting, stronger server infrastructure and production security controls. No account tokens are accepted. The architecture deliberately avoids databases and frameworks until needed. See ROADMAP.md.
