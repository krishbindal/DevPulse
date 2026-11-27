# DevPulse roadmap

- [x] Define initial scope, public GitHub metadata with provenance and unknown values.
- [x] Create responsive local dashboard and minimal scan endpoint.
- [x] Add mocked tests, input validation, request timeout and response size limit.
- [x] Create dedicated GitHub repository.
- [x] Land baseline pull request and verify CI (PR #1, run 46050193986).
- [ ] Verify live GitHub API from application runtime.
- [x] Implement GitHub language byte breakdown with source and explicit unavailable state (PR #2, CI run 46050493201).
- [x] Implement bounded tree inventory, manifest and workflow file discovery, and JSON export (PR #3, CI run 46050891136).
- [x] Implement latest public default-branch Actions run metadata (PR #4, CI run 46051011803).
- [x] Implement root npm dependency declarations from an immutable manifest blob (PR #5, CI run 46051141619).
- [x] Implement narrow root Python requirements declaration analysis (PR #6, CI run 46051342329).
- [x] Implement bounded npm package-lock v2/v3 version evidence (PR #9, CI run 46052131387).
- [x] Integrate supported npm lockfile assertions into opt-in advisory lookup (PR #10, CI run 46052360218).
- [ ] Additional Python formats and CI aggregation.
- [x] Implement opt-in OSV advisory ID lookup for supported exact declarations (PR #7, CI run 46051470056).
- [ ] Verify live OSV and GitHub runtime integration, parse lockfiles, add static security checks.
- [x] Implement local scan concurrency, rate limits and bounded TTL cache (pending PR CI).
- [ ] Harden production server and ingress, authorization if needed, deployment and performance testing.
- [ ] Add evidence-grounded AI explanations, adversarial tests and accessible UI review.
- [ ] Recruiter case study, architecture diagram, real benchmarks and authorized demo deployment.

## Progress
Local prototype created; eight local unit tests passed on mocked inputs. Public repository created by owner. Baseline PR #1 merged after successful GitHub Actions run 46050193986. Language breakdown merged after successful CI run 46050493201. Repository inventory and JSON export merged after successful CI run 46050891136. Latest Actions metadata and HTTP integration tests merged after successful CI run 46051011803. Root npm declarations merged after successful CI run 46051141619 (41 tests). Root Python requirements merged after successful CI run 46051342329 (48 tests). Opt-in OSV lookup merged after successful CI run 46051470056. Advisory coverage accuracy merged after successful CI run 46051939364 (61 tests on branch). Root npm lockfile evidence merged after successful CI run 46052131387 (69 tests on branch). Lockfile advisory integration merged after successful CI run 46052360218 (74 tests on branch). Local scan limits and cache proposed. No live scan or deployed service verified.
