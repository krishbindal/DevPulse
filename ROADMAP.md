# DevPulse roadmap

- [x] Define initial scope, public GitHub metadata with provenance and unknown values.
- [x] Create responsive local dashboard and minimal scan endpoint.
- [x] Add mocked tests, input validation, request timeout and response size limit.
- [x] Create dedicated GitHub repository.
- [x] Land baseline pull request and verify CI (PR #1, run 46050193986).
- [ ] Verify live GitHub API from application runtime.
- [x] Implement GitHub language byte breakdown with source and explicit unavailable state (PR #2, CI run 46050493201).
- [x] Implement bounded tree inventory, manifest and workflow file discovery, and JSON export (verify PR CI).
- [ ] Parse actual dependency versions and retrieve CI run metadata.
- [ ] Implement bounded static/security checks; distinguish not analyzed, no findings, and failure.
- [ ] Add production-grade rate limiting, caching, authorization if needed, and hardened web deployment.
- [ ] Add evidence-grounded AI explanations, adversarial tests and accessible UI review.
- [ ] Recruiter case study, architecture diagram, real benchmarks and authorized demo deployment.

## Progress
Local prototype created; eight local unit tests passed on mocked inputs. Public repository created by owner. Baseline PR #1 merged after successful GitHub Actions run 46050193986. Language breakdown merged after successful CI run 46050493201. Repository inventory and JSON export proposed; CI verification required. No live scan or deployed service verified.
