# WebShield – Automated Website and API Security Testing Platform

WebShield is a desktop cybersecurity application developed in Java for defensive website and API security assessments. It enables developers and security engineers to evaluate websites they own or are authorized to assess through automated crawling, structural discovery, and defensive security checks.

---

## Technical Stack

* **Language**: Java 21 LTS (Eclipse Temurin Hotspot)
* **User Interface**: JavaFX 21 (FXML + CSS)
* **Architecture**: Core Java (OOP, Encapsulation, Clean Separation of Concerns)
* **Build System**: Apache Maven 3.9+
* **HTML Parsing**: Jsoup 1.17.2
* **JSON Processing**: Jackson 2.17.0
* **Logging**: SLF4J 2.0.12 + Logback 1.5.3
* **Testing**: JUnit 5 (Jupiter 5.10.2)
* **Database**: MySQL 8+ via JDBC & Connection Management
* **Password Security**: BCrypt (`org.mindrot:jbcrypt`)

> **Design Principle**: WebShield is built entirely on Core Java and JavaFX. It avoids bloated enterprise frameworks (such as Spring Boot or Spring Security) and does not rely on external running ZAP/EvoMaster instances, APIs, or CLIs.

---

## Project Structure

```
WebShield/
├── pom.xml                               # Maven project configuration & dependencies
├── README.md                             # Setup, architecture, and execution guide
├── src/
│   ├── main/
│   │   ├── java/com/webshield/
│   │   │   ├── Main.java                 # Standard JVM application launcher
│   │   │   ├── MainApp.java              # JavaFX Application lifecycle & Stage manager
│   │   │   ├── config/                   # Configuration parameters & safety settings
│   │   │   ├── ui/
│   │   │   │   ├── controllers/          # FXML screen controllers (e.g. MainController)
│   │   │   │   └── components/           # Reusable UI widgets and custom cells
│   │   │   ├── auth/                     # Authentication, hashing, and session management
│   │   │   ├── website/                  # Target registration, scope & domain validation
│   │   │   ├── crawler/                  # Link discovery, form parsing, URL canonicalization
│   │   │   ├── http/                     # Java HttpClient manager, request/response handlers
│   │   │   ├── assessment/               # Defensive security analyzers & detection rules
│   │   │   ├── scan/                     # Multithreaded scan engine & progress trackers
│   │   │   ├── findings/                 # Vulnerability models, severity & evidence storage
│   │   │   ├── database/                 # JDBC connection pooling and DAO repositories
│   │   │   ├── models/                   # Core business domain entities
│   │   │   └── utils/                    # SSRF prevention, IP validation, formatters
│   │   └── resources/
│   │       ├── fxml/                     # FXML layout definitions (main.fxml)
│   │       ├── css/                      # Application styling (styles.css)
│   │       ├── images/                   # Icons and graphic assets
│   │       └── logback.xml               # Logback logging configuration
│   └── test/
│       └── java/com/webshield/           # JUnit 5 integration and unit test suite
```

---

## Setup and Execution Instructions

### Prerequisites
1. **Java Development Kit**: JDK 21 or later (`JAVA_HOME` pointed to JDK 21).
2. **Apache Maven**: Version 3.8 or 3.9+.

Verify your environment:
```bash
java -version
mvn -version
```

### Build the Project
Compile the source code and run all JUnit 5 verification tests:
```bash
mvn clean test
```

### Database Setup (Docker Compose)
Start the MySQL database container:
```bash
docker-compose up -d
```
The database will automatically initialize using `src/main/resources/database/schema.sql`.
Configure credentials in `src/main/resources/database.properties` (or copy from `database.properties.template`).

### Run the Application
Run the JavaFX application directly using the JavaFX Maven plugin:
```bash
mvn javafx:run
```

Or execute directly with Java:
```bash
mvn compile exec:java -Dexec.mainClass="com.webshield.Main"
```

---

## Security & Ethical Assessment Boundary
WebShield is designed exclusively for authorized testing and defensive educational purposes:
* Assessments are strictly confined to user-registered, authorized targets.
* Out-of-scope navigation and requests to private networks, loopback addresses, and cloud metadata services are blocked by default.
* Payloads are strictly non-destructive (utilizing safe canary strings and defensive error signature matching).

---

## Implemented Modules (Part 1.6 to 1.9)

### 1. Website Management
* **Target Registration & Validation**: Restricts testing exclusively to HTTP/HTTPS schemes, performs URL canonicalization, and enforces explicit authorization confirmation (`WebsiteValidator`).
* **CRUD & Scope Isolation**: Manages registered targets per authenticated user with full search, edit, delete, and detail tracking (`WebsiteService`, `WebsiteRepository`).
* **Target Details**: Detailed page with metric counters, interactive website structure `TreeView`, and discovered endpoints table.

### 2. Website Crawling and Discovery
* **Autonomous BFS Crawler**: Modeled after OWASP ZAP's spider architecture using breadcrumb depth tracking, visited URL tracking, and canonicalization (`WebCrawler`, `URLNormalizer`, `VisitedURLTracker`).
* **Jsoup-powered Link & Form Extraction**: Discovers HTML links (`<a>`, `<link>`, `<iframe>`) and forms (`<form>`, `<input>`, `<textarea>`, `<select>`, `<button>`) with attributes (`required`, `maxlength`, `pattern`).
* **Database Persistence**: Discovered pages, forms, and input fields are persisted transactionally to MySQL (`discovered_pages`, `forms`, `input_fields`).
* **Defensive Scope Guard**: Rejects static binary media (.png, .pdf, .zip, etc.) and enforces SSRF blocking against cloud metadata and private networks (`URLDiscovery`).

### 3. HTTP Communication Engine
* **Modern Java HttpClient**: Asynchronous and synchronous non-blocking transport with custom connection timeouts, user agent headers, and size limits (`HttpClientManager`).
* **Request & Response Models**: Structured representation of methods, headers, status codes, bodies, and timings (`HttpRequestData`, `HttpResponseData`, `HttpRequestBuilder`, `HttpResponseHandler`).
* **Security Header & Cookie Parsers**: Detailed inspection for security headers and full parsing of `Set-Cookie` directives including `HttpOnly`, `Secure`, and `SameSite` (`CookieParser`, `HttpHeaderAnalyzer`).
* **Safe Redirect Handler**: Re-validates redirect schemes and domains against the target's authorized scope (`RedirectHandler`).

### 4. Website Security Assessment Engine
* **Strategy Pattern Architecture**: Modular `AssessmentRule` implementations orchestrated by `SecurityAssessmentEngine`.
* **5 Assessment Categories**:
  1. **Security Headers**: Analyzes missing `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, and `Referrer-Policy`.
  2. **Cookie Security**: Flags cookies missing `HttpOnly`, `Secure`, or `SameSite` flags.
  3. **Input Reflection Analysis**: Tests query parameters with unique, non-destructive benign canary markers (`ws_probe_*`) to identify potential unescaped reflection without false-positive over-classification.
  4. **SQL Error Anomaly Detection**: Probes inputs with non-destructive syntax anomalies and matches responses against a comprehensive regex dictionary of DBMS error signatures (MySQL, PostgreSQL, Oracle, MS SQL Server, SQLite).
  5. **Input Validation Assessment**: Evaluates form fields for missing server-side input validation indicators.
* **Results & Evidence Storage**: Persists findings with severity, confidence, evidence excerpts, and remediation recommendations to `scan_findings` and `scans` tables.

---

## Implemented Modules (Part 1.10 to 1.12)

### 5. Scan Management Module (`com.webshield.scan`)
* **Scan Configuration**: Allows operators to customize crawl depth (1–10), maximum pages (1–500), request timeouts (1–120s), rate-limit delays (0–10,000ms), and granularly enable/disable assessment categories (`ScanConfiguration`).
* **Scan Execution Workflow**: Coordinates scan lifecycles through explicit states: `PENDING` ➔ `INITIALIZING` ➔ `CRAWLING` ➔ `ASSESSING` ➔ `SAVING_RESULTS` ➔ `COMPLETED` / `CANCELLED` / `FAILED` (`ScanStatus`, `ScanTask`).
* **Cooperative Cancellation**: Gracefully halts in-progress crawler and assessment threads without leaving uncommitted transactions or corrupt database states.
* **Scan Manager**: Thread-safe background execution backed by daemon `ExecutorService`, maintaining an active scan registry and dispatching `ScanExecutionResult` futures (`ScanManager`, `ScanService`).
* **Real-time Progress Tracker**: Thread-safe tracking of discovered pages, tested pages, remaining pages, checks completed, findings count, elapsed duration, and active operation status (`ScanProgressTracker`).

### 6. Vulnerability Finding Management Module (`com.webshield.findings`)
* **Structured Domain Model**: Unified `SecurityFinding` representing detected vulnerabilities with website association, OWASP category, target URL, affected parameter, HTTP method, severity, confidence level, finding review status, and structured evidence (`FindingEvidence`).
* **Finding Deduplication**: Eliminates duplicate alerts within a scan based on composite keys `(websiteId, url, parameter, category)`, retaining higher severity and richer evidence (`FindingDeduplicator`).
* **Finding Classification & Scoring**: Standardizes severity weights (0–10), overall risk scoring (0–100), and confidence heuristics (`FindingClassifier`).
* **Lifecycle & Audit History**: Supports finding review statuses (`Open`, `Under Review`, `Resolved`, `False Positive`) with audit trail logging of analyst updates (`FindingStatus`, `FindingHistoryService`, `FindingService`).

### 7. Scan Results Interface (`com.webshield.ui.controllers.ReportsController`)
* **Summary Cards**: 6 top metric cards displaying real-time counts for Total Findings, Critical, High, Medium, Low, and Informational findings.
* **Filterable & Searchable Findings Table**: Multi-parameter filtering by severity, vulnerability category, and review status, coupled with free-text search across finding names, URLs, and parameters.
* **Finding Inspector (Master-Detail)**: Full inspection panel displaying vulnerability descriptions, security impact, HTTP request headers and response evidence excerpts, remediation guidance, and status update controls (`False Positive`, `Resolved`, `Under Review`, `Open`).

### 8. Scan History Module (`com.webshield.ui.controllers.ScanHistoryController`)
* **Historical Scan Audit**: Tabular view of all previous security assessments with scan ID, target website, start timestamp, execution duration, status, pages tested, and findings count.
* **Results Navigation**: One-click "View Results" action and row double-click navigates directly to the Reports view pre-filtered for that specific scan.
* **Filtering & Searching**: Instant search by target name or scan ID, with dropdown filters for scan status and registered websites.

### 9. Dashboard Integration & Reliability
* **Dynamic Statistics**: Overview stat cards (Total Websites, Total Scans, Total Vulnerabilities, Critical Findings), severity distribution bar chart, and recent scan/target tables query MySQL directly for the authenticated operator.
* **Navigation Cache Invalidation**: Automatic cache invalidation ensures the dashboard displays up-to-date data immediately following scan completion.

---

## Implemented Modules (Part 2: Intelligent API Security Testing Engine)

### Module A: API Project Management and OpenAPI Import (`com.webshield.api.service`)
* **Project Organization**: Multi-tenant API project management isolating OpenAPI/Swagger specifications per operator (`ApiProjectService`, `ApiProjectEntity`).
* **Format Agnostic Import**: Imports JSON and YAML specifications via raw upload, file upload, or authorized URL endpoint retrieval (`ApiSpecificationImporter`).
* **Specification Validation**: Enforces size bounds, format checks, and metadata extraction prior to persistence.

### Module B: OpenAPI Parser and Endpoint Extractor (`com.webshield.api.parser`)
* **Multi-Version Support**: Complete parsing support for OpenAPI 3.0.x, 3.1.x, and Swagger 2.0 (`OpenApiParser`).
* **Local Reference Resolution**: High-performance internal `$ref` pointer resolution for component schemas and parameters (`SchemaResolver`).
* **Anti-SSRF & Cycle Protection**: Enforces `MAX_RECURSION_DEPTH = 30`, tracks active resolution stacks to prevent circular references, and blocks remote URL resolution for security.
* **Endpoint & Parameter Modeling**: Deconstructs operations into rich models (`ApiEndpoint`, `ApiParameter`, `RequestBodyDefinition`, `ResponseDefinition`).

### Module C: Rule-Based API Test-Case Generation (`com.webshield.api.generation`)
* **Constraint Awareness**: Extracts and respects types, min/max numbers, minLength/maxLength strings, formats (email, uuid, date-time), regex patterns, and enums.
* **Multi-Category Test Strategies**:
  * `VALID_SMOKE`: Generates baseline conforming requests satisfying all schema constraints.
  * `BOUNDARY`: Generates edge cases (min-1, max+1, empty strings, exact boundaries).
  * `MISSING_REQUIRED`: Systematically omits required headers, query params, and body fields.
  * `TYPE_CONFUSION`: Replaces integers with strings, objects with arrays, and booleans with null.
  * `SECURITY_PROBES`: Injects benign canary tokens (`ws_probe_*`, `' OR '1'='1`) to evaluate server sanitization.
* **Reproducibility**: Deterministic seeded generation via Java `Random(seed)` with automatic test-case deduplication.

### Module D: Input Mutation Engine (`com.webshield.api.mutation`)
* **Controlled Exploration**: Accepts valid or boundary test cases and systematically explores adjacent input spaces without uncontrolled random noise (`MutationEngine`).
* **Mutation Operators**: Boundary mutations, type confusion, null/empty injection, payload injection, format violations, and structural tampering (`MutationOperatorRegistry`).
* **Immutability & Lineage**: Deep-copy cloning guarantees original test cases are never modified in-place; mutated cases maintain parent-child lineage identifiers.

### Module E: Evolutionary Search & MIO Algorithm (`com.webshield.api.search`)
* **Many Independent Objective (MIO) Architecture**: Manages multi-objective fitness archives keyed by endpoint, method, status code class (2xx, 3xx, 4xx, 5xx), and vulnerability vectors (`ObjectiveArchive`, `SearchObjective`).
* **Candidate Selection & Elitism**: Balances exploitation of high-fitness individuals with exploration of unvisited objectives using tournament selection and adaptive mutation probabilities.
* **Budget & Termination**: Respects evaluation count limits, time budgets, convergence thresholds, and cooperative cancellation tokens.

### Module F: API Execution Engine (`com.webshield.api.execution`)
* **Defense-in-Depth Anti-SSRF**: `TargetSafetyValidator` strictly blocks loopback (`127.0.0.1`, `::1`), private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and cloud metadata (`169.254.169.254`, `metadata.google.internal`).
* **Redirect Revalidation**: Manual redirect tracer re-verifies destination schemes, domains, and IP bounds at every hop.
* **Traffic Shaping & Concurrency**: Token-bucket rate limiter (`RateLimiter`) and semaphore-controlled concurrency bounds protect target availability.
* **Memory & Safety Gates**: Streams and truncates response bodies exceeding 1 MB (`maxResponseSizeBytes`); mutating methods (`POST`, `PUT`, `PATCH`, `DELETE`) require explicit authorization.

### Module G: API Security Response Analysis (`com.webshield.api.analysis`)
* **7 Security Analysis Rules**:
  1. `SENSITIVE_DATA_EXPOSURE`: Identifies unredacted tokens, API keys, passwords, and private keys.
  2. `INFORMATION_DISCLOSURE`: Flags detailed DBMS stack traces, framework debug banners, and internal server paths.
  3. `SECURITY_HEADERS`: Checks API headers for missing HSTS, CSP, and content-type enforcement.
  4. `UNAUTHENTICATED_ACCESS`: Detects sensitive administrative operations reachable without credentials.
  5. `INJECTION_REFLECTION`: Detects unescaped reflection of probe markers in response bodies.
  6. `SERVER_ERROR_ANALYSIS`: Differentiates legitimate 500 errors from unhandled crashes.
  7. `INPUT_VALIDATION_FAILURE`: Identifies servers failing to enforce OpenAPI schema constraints.
* **Standard Mapping**: Direct mapping to OWASP API Top 10 (2023) and Common Weakness Enumeration (CWE).
* **Exception Isolation**: Analyzers run under isolated try-catch blocks to prevent faulty rules from halting the scan pipeline.

### Module H: API Persistence & Multi-Tenant Security (`com.webshield.api.service`)
* **Complete MySQL Persistence**: Stores scans, execution records, mutated test cases, security findings, and aggregate metrics in MySQL InnoDB tables (`api_scans`, `api_executions`, `api_findings`, `api_test_case_results`, `api_scan_statistics`).
* **Multi-User Isolation & Anti-IDOR**: All queries and mutations verify tenant ownership (`Objects.equals(entity.getUserId(), userId)`) throwing `SecurityException` upon mismatch.
* **Data Sanitization**: Automatically redacts Bearer tokens, Basic auth, API keys, and passwords before database write; truncates large response bodies to 64 KB.

### Module I: API Testing JavaFX User Interface (`com.webshield.ui.controllers`)
* **Comprehensive Screen Suite**: 10 dedicated FXML views and controllers for API project management, specification inspection, scan configuration, real-time execution console, test case tables, execution details, security findings, historical trends, and scan comparisons.
* **Asynchronous Execution**: All long-running search and execution operations run in background daemon threads with cooperative cancellation, updating UI via `Platform.runLater`.
* **Prototype Scoping**: All controllers are `@Scope("prototype")` Spring components, preventing UI state contamination across page transitions.

### Module J: Advanced Reporting & LLM Integration (`com.webshield.api.reporting`, `com.webshield.api.llm`)
* **Zero-Dependency PDF Generation**: Native ISO 32000-1 / PDF 1.4 binary document builder (`SimplePdfWriter`, `PdfReportGenerator`) with cover page, running headers/footers, A4 pagination, tables, colored severity badges, and code blocks.
* **Sanitized HTML Reports**: Fully standalone, responsive CSS reports (`HtmlReportGenerator`) with comprehensive HTML entity escaping and sensitive data redaction.
* **Sandboxed LLM Finding Explanations**: Pluggable AI integration (`LlmService`, `HttpLlmProvider`, `MockLlmProvider`) utilizing strict fenced prompt boundaries (`<<<UNTRUSTED_SCANNER_EVIDENCE>>>`), pre-transmission credential redaction, consent flags, and response XSS sanitization. AI explanations cannot alter scanner findings.

---

## Automated Verification Suite

The WebShield verification suite runs through Maven Surefire with 100% pass rate:

```bash
mvn clean test
```

* **Total Tests Executed**: 404
* **Passing**: 404
* **Failures**: 0
* **Errors**: 0
* **Skipped**: 0
* **Test Suites**: 51 suites spanning Part 1 Website Assessment, Part 2 Modules A–J, Spring Context Integration, and FXML resource validation.



