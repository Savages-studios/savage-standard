# SIA-v6 Million-Point Benchmark Report

**Run ID:** `035c76ec-696e-44a9-9174-0a1f953ea2ce`  
**Engine:** SIA-v6.2.0  
**Total Observations:** 1,000,000  
**Scenarios:** 25,000 (40 checkpoints each)  
**Certified:** 910,634 (91.06%)  
**Overall Mean Score:** 97.47 / 100  
**Measurement basis:** every observation is a real execution of the system's own operations — the agent symplectic core, the shared proof chain, the RG flow engine, the topological memory and agent, and the tollbooth's five metered utility endpoints — on inputs taken from the repository's own test fixtures. No simulated or sampled measurements.  
**Run integrity:** every record is bound to the run by an HMAC-SHA256 over its measured fields (derivation published in benchmark/integrity.py; the run seed re-derives the key). The proof-chain suite's declared tamper scenarios are included in the denominators above.  

## Suite Summary

| Suite | Points | Mean Score | Certified % |
|---|---:|---:|---:|
| adversarial_healing | 120,000 | 94.95 | 57.6% |
| causal_isolation | 100,000 | 98.00 | 98.0% |
| determinism_replay | 120,000 | 100.00 | 100.0% |
| hamiltonian_conservation | 150,000 | 100.00 | 100.0% |
| latency_throughput | 70,000 | 99.88 | 99.8% |
| memory_rg_decimation | 80,000 | 100.00 | 100.0% |
| proof_chain_integrity | 70,000 | 94.97 | 95.0% |
| symplectic_jacobian | 100,000 | 86.35 | 90.0% |
| topology_phase_transition | 80,000 | 99.98 | 71.4% |
| vertical_domain_stress | 110,000 | 100.00 | 100.0% |

## Operating Envelope

- **Max Safe Concurrency:** 998,000.00
- **Max Contained Attack Severity:** 1.00
- **Max Stable Horizon Steps:** 39.00
- **Max Throughput Ops:** 10,170.15

## Certification Gate

- Status: **CERTIFIED WITH DEGRADATION**
- Certified checkpoints: 91.06% (full >=95%; degraded >=85%; research >=70%)
- Mean metric score: 97.47 (full >=90; degraded >=80)
- Unmet gate: Full certification requires >=95% certified checkpoints and mean score >=90
