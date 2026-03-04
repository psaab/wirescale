# Claim Status Matrix

## Per-Document Distribution

| Document | Total Claims | Supported | Partially Supported | Needs Qualification | Unsupported | Outdated |
|---|---:|---:|---:|---:|---:|---:|
| `ARCHITECTURE.md` | 96 | 16 | 29 | 28 | 22 | 1 |
| `PERFORMANCE.md` | 96 | 16 | 16 | 27 | 35 | 2 |
| `ROUTABLE-PREFIX.md` | 129 | 40 | 24 | 51 | 12 | 2 |
| `SECURITY.md` | 102 | 13 | 11 | 16 | 56 | 6 |
| **Total** | **423** | **85** | **80** | **122** | **125** | **11** |

## Overall Signal

- `Supported + Partially Supported`: `165 / 423` (`39.0%`)
- `Needs Qualification + Unsupported + Outdated`: `258 / 423` (`61.0%`)
- Highest hard-risk concentration (`Unsupported + Outdated`): `SECURITY.md` (`62 / 102`, `60.8%`)
- Highest conditional-risk concentration (`Needs Qualification`): `ROUTABLE-PREFIX.md` (`51 / 129`, `39.5%`)

## Interpretation

1. The corpus is rich in design intent but frequently written in implementation-present tense.
2. Security and performance documents contain the largest volume of unverifiable or currently unsupported operational claims.
3. Architecture and routable-prefix documents have substantial correctness issues around address semantics, routing assumptions, and conditional statements presented as universal facts.
