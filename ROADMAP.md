# DevPulse roadmap

- [x] Define initial scope, public GitHub metadata with provenance and unknown values.
- [x] Create responsive local dashboard and minimal scan endpoint.
- [x] Add mocked tests, input validation, request timeout and response size limit.
- [x] Create dedicated GitHub repository.
- [x] Land baseline pull request and verify CI (PR #1, run 46050193986).
- [x] Verify live GitHub metadata/language/tree API paths from application runtime (PR #12, run 46052873282).
- [x] Implement GitHub language byte breakdown with source and explicit unavailable state (PR #2, CI run 46050493201).
- [x] Implement bounded tree inventory, manifest and workflow file discovery, and JSON export (PR #3, CI run 46050891136).
- [x] Implement latest public default-branch Actions run metadata (PR #4, CI run 46051011803).
- [x] Implement root npm dependency declarations from an immutable manifest blob (PR #5, CI run 46051141619).
- [x] Implement narrow root Python requirements declaration analysis (PR #6, CI run 46051342329).
- [x] Implement bounded npm package-lock v2/v3 version evidence (PR #9, CI run 46052131387).
- [x] Integrate supported npm lockfile assertions into opt-in advisory lookup (PR #10, CI run 46052360218).
- [ ] Additional Python formats and CI aggregation.
- [x] Implement opt-in OSV advisory ID lookup for supported exact declarations (PR #7, CI run 46051470056).
- [x] Verify live OSV fixture lookup (PR #12, run 46052873282).
- [x] Implement opt-in bounded Python AST heuristics (PR #13, runs 46053279036 and 46053279043).
- [x] Implement engineering practice evidence checklist (PR #14, runs 46053482042 and 46053482105).
- [ ] Expand static analysis coverage and live integration paths.
- [x] Implement local scan concurrency, rate limits and bounded TTL cache (PR #11, CI run 46052649601).
- [x] Add non-root local Docker packaging and container smoke workflow (PR #18, runs 46054515103, 46054514960, 46054514903 and 46054515000).
- [ ] Harden production server and ingress, authorization if needed, deployment and performance testing.
- [x] Implement grouped responsive dashboard with separate assets and stricter CSP (PR #15, runs 46053714299 and 46053714303).
- [x] Implement deterministic evidence-grounded next-step recommendations (PR #16, runs 46054013320 and 46054013342).
- [x] Add real Chromium dashboard regression workflow (PR #17, runs 46054255524 and 46054255445).
- [x] Offline report comparison CLI (merged PR #19).
- [ ] Browser-local report comparison (implementation proposed; CI pending).
- [ ] Add optional evidence-grounded AI explanations, adversarial tests and broader accessibility/cross-browser review.
- [ ] Recruiter case study, architecture diagram, real benchmarks and authorized demo deployment.

## Progress
Local prototype created; eight local unit tests passed on mocked inputs. Public repository created by owner. Baseline PR #1 merged after successful GitHub Actions run 46050193986. Language breakdown merged after successful CI run 46050493201. Repository inventory and JSON export merged after successful CI run 46050891136. Latest Actions metadata and HTTP integration tests merged after successful CI run 46051011803. Root npm declarations merged after successful CI run 46051141619 (41 tests). Root Python requirements merged after successful CI run 46051342329 (48 tests). Opt-in OSV lookup merged after successful CI run 46051470056. Advisory coverage accuracy merged after successful CI run 46051939364 (61 tests on branch). Root npm lockfile evidence merged after successful CI run 46052131387 (69 tests on branch). Lockfile advisory integration merged after successful CI run 46052360218 (74 tests on branch). Local scan limits and cache merged after successful CI run 46052649601 (82 tests on branch). Live GitHub and OSV smoke checks passed in PR #12 (run 46052873282; 84 unit tests in run 46052873217). Python static review merged after successful unit and live workflows (94 tests). Engineering practice checklist merged after successful unit and live workflows (101 tests). Dashboard navigation and CSP improvements merged after successful unit and live workflows (105 tests). Deterministic evidence-based recommendations merged after successful unit and live workflows (113 tests). Chromium dashboard regression workflow merged after 4 browser tests and 113 Python tests passed. Local Docker packaging merged after all four workflows passed (116 Python tests and 4 browser tests). Offline comparison CLI merged in PR #19. Browser-local comparison proposed. No deployed service verified.
