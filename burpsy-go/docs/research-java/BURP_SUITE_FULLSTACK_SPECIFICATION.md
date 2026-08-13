# Burp Suite Professional Fullstack Application Architecture & Implementation Specification
**Document Version:** 1.0.0  
**Target Architecture:** Decoupled Headless Core Engine (CLI/Daemon API) + Swing/FlatLaf Desktop GUI Client  
**Reference Architecture:** Burp Suite Professional v2026.7.1 (Deobfuscated & Reverse Engineered)  
**Authoritative Sources:** `SCAN_ENGINE.md`, `SCANNER_MAP.md`, `UI_FILES_MAP.md`, `BURP_SUITE_UI_UX_SPECIFICATION.md`, `out/clean/renamed_final`, `out/reconstructed/NAMEMAP.md`

---

## 1. Executive System Architecture & Topology

The reverse-engineered Burp Suite system architecture is a decoupled, event-driven, multi-threaded security platform. While packaged as a single desktop application, its internal engineering strictly enforces a clean boundary between the **Headless Traffic/Security Engine** and the **Swing GUI Presentation Layer**.

```
+---------------------------------------------------------------------------------------------------+
|                                      SWING / FLATLAF GUI CLIENT                                    |
|  +---------------+  +---------------+  +---------------+  +---------------+  +-----------------+  |
|  | Dashboard GUI |  |   Target GUI  |  |   Proxy GUI   |  |  Repeater GUI |  |  Intruder GUI   |  |
|  +---------------+  +---------------+  +---------------+  +---------------+  +-----------------+  |
|          |                  |                  |                  |                   |           |
|          +------------------+------------------+------------------+-------------------+           |
|                                       | (Guice DI / Event Bus)                                    |
+---------------------------------------|-----------------------------------------------------------+
                                        |
+---------------------------------------v-----------------------------------------------------------+
|                                    CORE ENGINE BOUNDARY                                           |
|                                                                                                   |
|  +-------------------------+   +-------------------------+   +---------------------------------+  |
|  |   Netty HTTP/S Proxy    |   |  Automated Scan Engine  |   |    Montoya Extension Engine     |  |
|  |  (Intercept, CA, ALPN)  |   | (Zuq / Zcud / BChecks)  |   |   (IPC, Classloader, Hooks)     |  |
|  +-------------------------+   +-------------------------+   +---------------------------------+  |
|               |                             |                                 |                   |
|               +-----------------------------+---------------------------------+                   |
|                                             |                                                     |
|  +------------------------------------------v--------------------------------------------------+  |
|  |                         PERSISTENCE & LOGGING ENGINE (`.burp`)                               |  |
|  |    (Append-Only Binary Traffic Log + SQLite Metadata Index + Off-Heap Memory Buffers)       |  |
|  +---------------------------------------------------------------------------------------------+  |
+---------------------------------------------------------------------------------------------------+
```

### 1.1 Architectural Guarantees & Constraints
1. **Headless Engine Autonomy**: The Netty proxy, crawling/audit engine, and project persistence MUST run fully headless without any AWT/Swing dependencies.
2. **Zero-Copy Memory-Mapped Storage**: Traffic logs write to append-only binary files. Audit queue items store `(offset, length)` pointers into the traffic file rather than duplicating HTTP byte arrays in RAM.
3. **Pluggable Tool Modules**: Every tool (`PROXY`, `REPEATER`, `SCANNER`, etc.) is bound as a Guice module (`com.google.inject.AbstractModule`) implementing standard lifecycle interfaces (`ToolFrameProvider`, `ToolTabFlasher`).
4. **Deterministic UI Component Addressability**: Every interactive Swing component MUST register a unique `setName("camelCaseComponentName")` to support automated testing and accessibility mapping.

---

## 2. Network & Proxy Subsystem Specification

### 2.1 Netty HTTP/S Proxy Pipeline
- **Core Technology**: Netty 4.x non-blocking I/O event loop group.
- **Listener Management**: Configurable TCP socket listeners (default `127.0.0.1:8080`, supporting transparent proxying, invisible proxying, and multi-port bindings).
- **Protocol Support**: HTTP/1.0, HTTP/1.1, HTTP/2 via ALPN negotiation, WebSockets (`ws://` and `wss://`).

```
Client Request ---> [ Listener Port ] 
                         |
                         v
             [ Dynamic TLS Interceptor ] (Generates per-host cert signed by Burp CA)
                         |
                         v
             [ Proxy Intercept Gate ] --(Intercept ON & Matches Rule?)--> [ Hold in GUI Queue ]
                         | (Forwarded)
                         v
             [ Match & Replace Engine ] (Regex request header/body rewriting)
                         |
                         v
             [ Upstream Proxy Router ] (Direct / SOCKS4 / SOCKS5 / HTTP Proxy Chain)
                         |
                         v
                 Target Web Server
```

### 2.2 Dynamic TLS Interception & Certificate Authority (CA)
- **Root CA Storage**: Generates a 2048-bit RSA Root Certificate Authority (`PortSwigger CA`) on initial startup, saved to user configuration key-store.
- **On-the-Fly Host Cert Generation**: When a client issues `CONNECT target.com:443`, the proxy dynamically mints an X.509 certificate for `target.com` containing appropriate Subject Alternative Names (SANs) signed by the local Root CA.

### 2.3 Match & Replace Engine
- Evaluates rules per request/response against 6 match scopes: `Request Header`, `Request Body`, `Response Header`, `Response Body`, `Request Param Name`, `Request Param Value`.
- Supports PCRE regex substitution and literal replacement.

---

## 3. Scanning Engine & Automated Audit Subsystem

The scanning engine is a data-driven, lazy-evaluated audit pipeline.

### 3.1 Task Execution Pipeline & State Machine
Burp Scanner runs 5 distinct task configurations via `Zrb9`:
1. `Crawl`: Headless DOM navigation & URL discovery.
2. `Audit`: Vulnerability testing against existing sitemap items.
3. `Crawl + Audit`: Combined discovery and vulnerability scanning.
4. `Live Audit`: Active scanning fed dynamically from Proxy traffic.
5. `Live Passive Crawl`: Sitemap populator fed passively from Proxy traffic.

#### Resilience Circuit Breaker (`Zgff`)
The engine implements a 2-level circuit breaker to manage target errors without crashing:
- **Level 1 (Insertion Point Level)**: $N$ check failures $ightarrow$ abort current insertion point.
- **Level 2 (Audit Item Level)**: $M$ insertion point failures $ightarrow$ mark audit item `FAILED`.
- **Level 3 (Task Level)**: High error threshold percentage $ightarrow$ automatically pause scan task.

### 3.2 Insertion Point Generator (`Zuq`)
Converts 1 HTTP Request into $N$ isolated attack positions.

| Insertion Point Scope | Targets | Relocation & Nesting Logic |
|---|---|---|
| `URL Query Params` | `GET` query values | Relocates parameters to POST body to test parser inconsistencies. |
| `Body Params` | Form-encoded / Multipart values | Swaps body parameters to URL query. |
| `JSON / XML Body` | Tree leaf values & key names | Recurses into nested encodings (JSON-in-param, Base64-in-JSON). |
| `HTTP Headers` | `User-Agent`, `Referer`, `Origin`, `Cookie` | Synthesizes extra headers if missing. |
| `REST Path Segments` | `/api/v1/user/{id}` | Treats URL path directory tokens as parameter insertion points. |

### 3.3 Check Dispatch & Lazy Execution (`Zcud`)
- **Lazy Factory (`Zb79<T>`)**: Scan checks are **never** instantiated up front.
- **Two-Stage Filter**:
  1. `Zwy6<T>.ZP()`: Evaluates check descriptor metadata against scan config.
  2. `Zwy6<T>.Zc()`: Checks target technology (e.g. skip SQLi check if target is static `.png`).
  3. Instantiates check instance only when target passes pre-filtering.

### 3.4 Vulnerability Catalog (`Zcot`)
- **183 Pre-defined Issue Types**: Defined in `resources/KnowledgeBase/Issues/*.json`.
- **Severity Tiers**: `HIGH`, `MEDIUM`, `LOW`, `INFORMATION`.
- **Confidence Tiers**: `CERTAIN`, `FIRM`, `TENTATIVE`.

### 3.5 BCheck DSL Interpreter Engine (`Zht9`)
Data-driven check definitions written in BCheck DSL:

```bcheck
metadata:
    language: v2-beta
    name: "Custom Header Injection Check"
    author: "Security Team"

define:
    target_header = "X-Custom-Test"

given insertion point then
    send payload:
        appending: "var_payload_123"

    if response contains "var_payload_123" then
        report issue:
            severity: high
            confidence: certain
            detail: "Custom header injection vulnerability identified."
            remediation: "Sanitize user inputs."
```

### 3.6 Issue Deduplication & Consolidation (`Zbvp`)
- Chain-of-responsibility dedup pipeline.
- Uses CRC signature (`Zby4`) over the issue type, host, and normalized path to merge duplicate findings cleanly.

---

## 4. Project Engine & Persistence Layer

### 4.1 Storage Architecture (`.burp` Project File)
- **Append-Only Traffic Log**: Raw HTTP requests and responses stream directly into an append-only binary log file (`.burp.log`).
- **Metadata Index (SQLite)**: SQLite database storing request/response index records (`id`, `tool_id`, `url`, `method`, `status_code`, `response_len`, `log_offset`, `log_length`, `timestamp`).
- **Off-Heap Memory Buffers**: Lowers RAM overhead by storing active UI table rows as lightweight 32-byte struct pointers pointing to disk offsets.

---

## 5. Montoya Extension Engine & Plugin Hooks

- **Extension Sandbox**: Isolated `URLClassLoader` per extension.
- **Public API Contract (`burp.api.montoya.*`)**:
  - `burp.api.montoya.proxy`: Intercept & history modification hooks.
  - `burp.api.montoya.scanner`: Register custom active/passive scan checks.
  - `burp.api.montoya.ui`: Add custom menu items, settings panels, and HTTP message editor tabs.

---

## 6. Burp AI & Bambda Subsystem Architecture

### 6.1 Hakawai AI Gateway Client (`HakawaiHttpClient`)
- Communicates with PortSwigger AI infrastructure (`https://ai.portswigger.net` API v1):
  - `explain-this`: Generates natural language summaries for request/response pairs and issues.
  - `recorded-login-generator`: AI-assisted login script generator.
  - `broken-access-control`: Automated BAC vulnerability exploration.

### 6.2 Bambda Engine
- **Dynamic Bytecode Compiler**: Uses `javax.tools.JavaCompiler` at runtime to compile user-supplied Java expressions into executable filter lambdas for Proxy History and HTTP tables.

---

## 7. Frontend UI/UX Architecture & Design System

*(Summary of the comprehensive specification detailed in `BURP_SUITE_UI_UX_SPECIFICATION.md`)*

- **FlatLaf Theme System**: Token-based color resolution (`Swatches` $ightarrow$ `Palettes` $ightarrow$ `UI Colors`).
- **15 Core Tools**: `DASHBOARD`, `TARGET`, `PROXY`, `SCANNER`, `INTRUDER`, `REPEATER`, `COLLABORATOR`, `SEQUENCER`, `COMPARER`, `LOGGER`, `ORGANISER`, `BURP_AI`, `EXTENDER`, `REPLAYER`, `DISCOVER`.
- **UI Component Addressability**: All Swing controls explicitly register via `setName("camelCaseComponentName")`.

---

## 8. Fullstack Implementation & Deployment Roadmap

```
+-----------------------------------------------------------------------------------+
| PHASE 1: NETTY PROXY CORE & STORAGE PIPELINE                                     |
| - Netty HTTP/1.1 & HTTP/2 ALPN listener                                          |
| - Dynamic SSL/TLS Certificate Authority & Host Cert Minter                        |
| - Binary Append-Only Traffic Log & SQLite Metadata Store                          |
+-----------------------------------------------------------------------------------+
                                      |
                                      v
+-----------------------------------------------------------------------------------+
| PHASE 2: SCAN ENGINE & BCHECK INTERPRETER                                         |
| - Insertion Point Generator (`Zuq`) & Scope Relocation Engine                     |
| - Lazy Check Dispatcher (`Zcud`) & Circuit Breaker (`Zgff`)                       |
| - BCheck DSL Interpreter (`Zht9`) & Issue Deduplicator (`Zbvp`)                  |
+-----------------------------------------------------------------------------------+
                                      |
                                      v
+-----------------------------------------------------------------------------------+
| PHASE 3: EXTENSION ENGINE & MONTOYA API BRIDGES                                   |
| - Extension Classloader Sandbox                                                   |
| - Montoya Proxy, Scanner, UI, and Repeater API Bridges                            |
+-----------------------------------------------------------------------------------+
                                      |
                                      v
+-----------------------------------------------------------------------------------+
| PHASE 4: FLATLAF DESKTOP GUI CLIENT & TOOL SUITE                                  |
| - FlatLaf Design System (Color Tokens, Base Containers, Monospace Editor)         |
| - 15 Tool UI Modules (Dashboard, Target, Proxy, Repeater, Intruder, AI)           |
| - `setName()` Component Addressability Audit & Integration Tests                 |
+-----------------------------------------------------------------------------------+
```
