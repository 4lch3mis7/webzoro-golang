# Webzoro

Fast network reconnaissance, port scanning, service enumeration, and vulnerability scanner.

## Prerequisites

Ensure the following tools are in your `PATH`:
- [nmap](https://nmap.org/)
- [subfinder](https://github.com/projectdiscovery/subfinder)
- [nuclei](https://github.com/projectdiscovery/nuclei)
- [ffuf](https://github.com/ffuf/ffuf)

## Installation

```bash
go build -o webzoro main.go
```

## Usage

```bash
# Scan a domain or IP (scans all 65,535 ports)
./webzoro <host>

# Enable verbose mode
./webzoro <host> -v
```

## Terminal Colors

Webzoro includes colorized status badges and severity indicators:
- `[*]`: Action / in progress
- `[+]`: Discovered finding / success
- `[!]`: Warning or critical finding
- `[-]`: Error / failure
- `[i]`: Informational notice

Vulnerability severities (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) and exploit states (KEV / active PoCs) are highlighted automatically. The [`NO_COLOR`](https://no-color.org/) standard is respected.

## HTTP Service Audit

```
                    ┌────────────────────────────────────────┐
                    │          HTTP Service Audit            │
                    └──────────────────┬─────────────────────┘
                                       │
        ┌──────────────────────────────┼──────────────────────────────┐
        ▼                              ▼                              ▼
 ┌──────────────┐              ┌──────────────┐               ┌──────────────┐
 │ TLS & Conn   │              │ Security     │               │ HTTP Methods │
 │ - HTTPS / TLS│              │ Headers      │               │ - OPTIONS    │
 │ - Cert valid │              │ - HSTS, CSP  │               │ - Dangerous: │
 │ - Expiration │              │ - X-Frame    │               │   PUT,TRACE  │
 │ - Self-signed│              │ - Server leak│               │ - WebDAV     │
 └──────────────┘              └──────────────┘               └──────────────┘
        │                              │                              │
        └──────────────────────────────┼──────────────────────────────┘
                                       │
        ┌──────────────────────────────┴──────────────────────────────┐
        ▼                                                             ▼
 ┌───────────────────────────┐                 ┌─────────────────────────────┐
 │ CORS & Cookie Security    │                 │ High-Risk File Probing      │
 │ - Reflected Origin & Creds│                 │ - robots.txt / sitemap      │
 │ - Missing HttpOnly/Secure │                 │ - /.git/HEAD & /.env        │
 │ - SameSite attributes     │                 │ - Swagger / API docs        │
 └───────────────────────────┘                 └─────────────────────────────┘
```

## Heuristic Parameter & IDOR Mining Engine

### How Intuition Maps to Code

| What Your Eyes Detect | The Underlying Pattern | Automated Heuristic in Webzoro |
| :--- | :--- | :--- |
| **REST Direct References** (`/api/v1/users/42`, `/orders/9921/status`, `/doc/3fa85f64-...`) | Path contains an entity noun followed by an identifier (numeric ID, UUID, slug). | **REST Entity & ID Extractor**: Detects IDs in paths, identifies the parent resource (`user`, `order`, `doc`), and synthesizes corresponding query/body parameters (`id`, `user_id`, `userId`, `order_id`). |
| **Entity Endpoints Without Parameters** (`/view_invoice.php`, `/api/profile`, `/download.php`) | The route implies an operation on a resource, but the parameter isn't visible in the link. | **Predictive Contextual Parameter Generator**: Extracts nouns (`invoice`, `profile`) and verbs (`download`, `view`, `edit`) to generate probable parameters (`invoice_id`, `id`, `user_id`, `file`, `path`, `filename`). |
| **Modern JS Route Literals** (`` fetch(`/api/user/${userId}`) ``, `axios.get('/doc/' + id)`) | SPA frontend dynamically injects variables into URLs. | **JS Template & Concatenation Parser**: Parses backtick template literals (`` `/route/${var}` ``) and concatenation patterns (`'/path/' + id`), extracting `userId` and `id` as direct parameters. |
| **Hidden Form Inputs** (`<input type="hidden" name="account_id" value="105">`) | Backend passes state or authorization contexts client-side. | **High-Value Input Tagging**: Prioritizes hidden inputs and tags them as high-confidence IDOR/privilege candidates. |
| **High-Risk Parameter Names** (`user_id`, `role`, `tenant_id`, `order_no`, `account`) | Parameters that directly control object reference or privilege level. | **Parameter Classification & IDOR Candidate Tagging**: Categorizes parameters into `Object Reference (IDOR)`, `Privilege / Role`, and `Resource / File Path`. |

---

### Design for `scanner/extract.go`

```
┌────────────────────────────────────────────────────────┐
│   Collected Assets (Probed Hits, HTML Responses, JS)   │
└───────────────────────────┬────────────────────────────┘
                            │
       ┌────────────────────┼────────────────────┐
       ▼                    ▼                    ▼
[REST & Path Analyzer]  [JS Template/AST]    [HTML Hidden Form]
  - Numeric IDs (/42)     - `${userId}`        - type="hidden"
  - UUIDs / Hex Hashes    - '/api/' + id       - JSON payload keys
  - Entity Nouns          - axios / fetch      - Data attributes
       │                    │                    │
       └────────────────────┼────────────────────┘
                            ▼
     [Semantic Parameter Inference & IDOR Classifier]
       1. Maps entities to permutations: {noun}_id, {noun}Id, id, {noun}_no
       2. Maps action verbs: download -> file, path, filename, doc_id
       3. Flags direct object references (IDOR Candidates)
                            │
                            ▼
     [Target Artifacts in .local/<target>/]
       - params.txt           (Raw deduplicated parameters)
       - params_inferred.txt  (Target-specific inferred wordlist for fuzzing)
       - idor_candidates.json (Structured endpoints with entities and candidate params)
       - idor_candidates.txt  (Ready-to-fuzz URLs: /api/users?user_id=FUZZ)
```