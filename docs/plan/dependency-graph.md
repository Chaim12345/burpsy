# Task Dependency Graph

```mermaid
graph TD
    subgraph P1 [Phase 1: Security & Scope (11)]
        T1 --> T1N
    end
    subgraph P2 [Phase 2: Intruder (16)]
        T2 --> T2N
    end
    subgraph P3 [Phase 3: Sequencer (15)]
        T3 --> T3N
    end
    subgraph P4 [Phase 4: Session (14)]
        T4 --> T4N
    end
    subgraph P5 [Phase 5: Core Tools (31)]
        T5 --> T5N
    end
    subgraph P6 [Phase 6: UI Shell (39)]
        T6 --> T6N
    end
    P1 --> P2 --> P3 --> P4 --> P5 --> P6
```

Phases sequential; within each phase issues close one-by-one in priority order (P0 → P1 → P2 → P4).
