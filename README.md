# WebShield – Automated Website and API Security Testing Platform

[![Java](https://img.shields.io/badge/Java-21%20LTS-orange.svg)](https://www.oracle.com/java/)
[![JavaFX](https://img.shields.io/badge/JavaFX-21.0.2-blue.svg)](https://openjfx.io/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.2.5-brightgreen.svg)](https://spring.io/projects/spring-boot)
[![MySQL](https://img.shields.io/badge/MySQL-8.0-blue.svg)](https://www.mysql.com/)
[![AI Model](https://img.shields.io/badge/Google%20Gemini-3.1%20Flash%20Lite-purple.svg)](https://ai.google.dev/)
[![Tests](https://img.shields.io/badge/Tests-408%2B%20Passing-success.svg)](src/test/java)

---

## 🎥 Full Video Demonstration

<div align="center">
  <video src="Video Project 3.mp4" controls width="100%" style="width: 100%; max-width: 100%; height: auto; border-radius: 8px; box-shadow: 0 6px 20px rgba(0,0,0,0.25);" playsinline>
    <source src="Video Project 3.mp4" type="video/mp4">
    <source src="proje.mp4" type="video/mp4">
    <p>Your browser or Markdown viewer does not support embedded videos. You can play or download the presentation directly: <a href="Video Project 3.mp4"><b>Video Project 3.mp4</b></a>.</p>
  </video>
</div>

<p align="center">
  <i>Full walkthrough covering authentication, website crawling, XSS/SQLi vulnerability detection, OpenAPI specification ingestion, test case synthesis, MIO evolutionary fuzzing, regression diffing, and Google Gemini AI report generation.</i>
</p>

---

## 🎓 Academic Project Report & Team Information

**Institution:** SRM University AP  
**Department:** Computer Science and Engineering  
**Academic Years:** [2024–2028]  
**Faculty Guide:** Dr. Isunuri Bala Venkateswarlu (Assistant Professor, Dept. of CSE)  
**Date of Submission:** 23-11-2026  

📄 **Full Project Report:** Complete 11-chapter formal academic documentation is available in [PROJECT_REPORT.md](PROJECT_REPORT.md).

### Team Members & Contributions

| Member | Registration No. | Main Responsibility Area | Key Deliverables |
| :--- | :--- | :--- | :--- |
| **Hasini** | AP24110011843 | Application Foundation & Authentication | JavaFX + Spring Boot lifecycle (`MainApp`), BCrypt Auth (`PasswordService`, `AuthValidator`), Dashboard command center, Spring Data JPA / MySQL entities. |
| **Sahithi** | AP24110011878 | Website Security Testing & Crawling | Jsoup crawling (`WebCrawler`, `FormExtractor`), XSS active canary reflection (`InputReflectionAnalyzer`), SQL error signatures (`SqlErrorAnalyzer`), background scanning (`ScanTask`). |
| **Namratha** | AP24110011814 | OpenAPI Parsing & Test Generation | Swagger parsing (`OpenApiParser`), Conformance/Boundary/Invalid test generators (`BoundaryValueGenerator`), Mutation engine, MIO evolutionary search (`EvolutionaryTestEngine`). |
| **Aruna** | AP24110011842 | API Execution, Diffs & AI Reporting | Rate-limited HTTP fuzzer (`ApiExecutionEngine`), OWASP API Top 10 rules (`ApiSecurityAnalyzer`), scan comparison engine (`ApiPersistenceService`), real Gemini LLM integration (`GeminiLlmProvider`), zero-dependency PDF writer. |


---

## 🚀 Key Features

* **Dual Testing Architecture**: Unified platform for both traditional multi-page HTML web applications and RESTful API endpoints.
* **Autonomous Web Crawling**: Jsoup-driven spider following internal link boundaries, extracting HTML forms, HTTP methods, and input controls.
* **Active Web Vulnerability Detection**:
  * *Reflected XSS*: Unique UUID canary token probing (`ws_probe_...`) verifying unencoded reflection in response bodies.
  * *SQL Injection*: Multi-DBMS error signature matching across MySQL, PostgreSQL, MSSQL, Oracle, and SQLite.
  * *Security Headers*: Detection of missing CSP, HSTS, X-Frame-Options, and X-Content-Type-Options.
  * *Cookie Security*: Inspection of `Set-Cookie` directives for missing `Secure`, `HttpOnly`, and `SameSite` attributes.
* **OpenAPI / Swagger Ingestion**: Ingests OpenAPI 3.x and Swagger 2.0 specifications in JSON or YAML format with remote entity resolution disabled (preventing SSRF).
* **Algorithmic Test Case Generation**:
  * *Valid Inputs*: Schema-compliant conformance payloads.
  * *Boundary Values*: Min/max numbers, length boundaries, character overflows.
  * *Invalid Inputs*: Schema type mismatches, missing required parameters, malformed syntax.
  * *Mutation Fuzzing*: Systematic bit, regex, syntax, and JSON structural perturbations.
* **Many-Objective Optimization (MIO)**: Generational evolutionary search optimizing test suites toward maximum endpoint coverage and fault discovery.
* **Asynchronous HTTP Fuzzer**: Built on Java 21 `HttpClient` with token-bucket rate limiting (QPS), concurrency semaphores, and target safety validation.
* **OWASP API Top 10 Analysis**: Fault-isolated rule evaluation mapping findings to standard CWE identifiers.
* **Differential Scan & Regression Engine**: Direct version-to-version diffing showing **New Regressions**, **Resolved Findings**, and **Persistent Issues** with mutual exclusion and one-click swap (`⇄`).
* **Google Gemini AI LLM Integration**: Direct REST API calls to Google AI Studio (`gemini-3.1-flash-lite`) providing root-cause explanations and remediation code with zero mock fallback.
* **Zero-Dependency PDF Engine**: Spec-compliant ISO 1.4 byte-stream builder generating publication-ready reports with tables, banners, and pagination without external dependencies.

---

## 🛠️ Technology Stack

| Component | Technology | Version | Purpose |
| :--- | :--- | :--- | :--- |
| **Language** | Java Standard Edition | **21 LTS** | Core language (Records, pattern matching, `HttpClient`) |
| **GUI Framework** | OpenJFX (JavaFX) | **21.0.2** | Native desktop UI with FXML and CSS |
| **Application IoC** | Spring Boot | **3.2.5** | Dependency injection, lifecycle management |
| **Persistence / ORM** | Spring Data JPA / Hibernate | **3.2.5** | Entity mapping and repository abstraction |
| **Database** | MySQL Server / Connector/J | **8.0 / 8.3.0** | Relational data persistence |
| **Connection Pool** | HikariCP | **5.1.0** | High-performance JDBC connection pooling |
| **HTML Crawler** | Jsoup | **1.17.2** | DOM traversal, link discovery, and form extraction |
| **API Parser** | Swagger Parser v3 | **2.1.20** | OpenAPI v2 & v3 JSON/YAML parsing |
| **JSON/YAML Engine** | Jackson Databind & SnakeYAML | **2.17.0** | Data serialization and Gemini REST payload formatting |
| **Password Hashing** | jBCrypt | **0.4** | Salted one-way BCrypt hashing |
| **HTTP Engine** | Java HTTP Client | **Java 21** | Asynchronous HTTP/2 and HTTP/1.1 transport |
| **AI LLM Engine** | Google Gemini REST API | `gemini-3.1-flash-lite` | Real-time remediation and vulnerability explanation |
| **PDF Engine** | SimplePdfWriter (Custom) | **PDF 1.4** | Native zero-dependency PDF document generation |
| **Testing** | JUnit 5 & Mockito | **5.10.2 / 5.11.0** | Automated test suite (408+ passing tests) |

---

## 📂 Project Structure

```
WebShield/
├── pom.xml                               # Maven project configuration & dependencies
├── docker-compose.yml                    # MySQL 8 database container configuration
├── README.md                             # Project overview, setup, and presentation guide
├── PROJECT_REPORT.md                     # Complete academic project report (SRM University AP)
│
├── src/main/java/com/webshield/
│   ├── Main.java                         # Standard JVM application bootstrap
│   ├── MainApp.java                      # JavaFX + Spring Boot integration launcher
│   ├── WebShieldApplication.java         # Spring Boot @SpringBootApplication class
│   │
│   ├── api/                              # API Security Testing Engine
│   │   ├── analysis/                     # OWASP API Top 10 rules, CWE mapping, findings
│   │   ├── dto/                          # Immutable Data Transfer Objects
│   │   ├── execution/                    # Rate-limited HTTP execution engine, safety validator
│   │   ├── generation/                   # Valid, Boundary, Invalid test generators
│   │   ├── llm/                          # Google Gemini LLM provider, prompt builder, service
│   │   ├── models/                       # OpenAPI domain models (Endpoints, Schemas)
│   │   ├── mutation/                     # Mutation engine & genetic operators
│   │   ├── parser/                       # OpenAPI 3.x / Swagger 2.0 parsers
│   │   ├── reporting/                    # API PDF report generator & SimplePdfWriter
│   │   ├── repository/                   # Spring Data JPA repositories for API domain
│   │   ├── search/                       # Evolutionary MIO search engine & fitness scoring
│   │   └── service/                      # Persistence service & scan comparison engine
│   │
│   ├── assessment/                       # Website Security Analyzers (XSS, SQLi, Headers, Cookies)
│   ├── auth/                             # BCrypt password hashing, validation, session manager
│   ├── config/                           # SpringContext bean registry
│   ├── crawler/                          # Jsoup crawler, link/form/input extractors
│   ├── dashboard/                        # Telemetry repository, service, command center metrics
│   ├── database/                         # JPA Entities & repositories
│   ├── findings/                         # Finding deduplication, classification, lifecycle
│   ├── http/                             # Website HTTP request manager & response handlers
│   ├── models/                           # User, Website, and Scan domain models
│   ├── scan/                             # Multithreaded scan engine & progress trackers
│   ├── ui/                               # JavaFX controllers & dialogs
│   └── website/                          # Website management service & AI reporting
│
├── src/main/resources/
│   ├── application.properties            # Database connection & pooling config
│   ├── css/styles.css                    # Professional dark navy desktop styling
│   ├── database/                         # SQL migration schemas (01 through 04)
│   └── fxml/                             # JavaFX FXML screen templates
│
└── src/test/java/com/webshield/          # Comprehensive JUnit 5 test suite (408+ tests)
```

---

## ⚡ Quick Start Instructions

### Prerequisites
* **Java Development Kit**: JDK 21 LTS or newer.
* **Apache Maven**: Version 3.8+ or 3.9+.
* **Docker & Docker Compose**: For running the MySQL 8 database.

---

### Step 1: Start the MySQL Database
From the project root directory, run:
```bash
docker compose up -d
```
*(Starts the `webshield-mysql` container on port `3306` with all schemas auto-initialized).*

---

### Step 2: Configure Gemini API Key
To enable real Google Gemini AI security report generation, set the environment variable:

* **Windows PowerShell**:
  ```powershell
  $env:GEMINI_API_KEY="your_google_ai_studio_api_key_here"
  ```
* **Windows Command Prompt (CMD)**:
  ```cmd
  set GEMINI_API_KEY=your_google_ai_studio_api_key_here
  ```
* **Linux / macOS**:
  ```bash
  export GEMINI_API_KEY="your_google_ai_studio_api_key_here"
  ```

---

### Step 3: Run the Application
Launch the WebShield desktop application:
```bash
mvn javafx:run
```
*(Alternatively, execute directly via `mvn compile exec:java -Dexec.mainClass="com.webshield.Main"`).*

---

### Step 4: Run Tests
Run the entire 408+ test verification suite:
```bash
mvn test
```

---

## 💻 Key Code Implementation Highlights

### 1. Dual Container Startup (`MainApp.java`)
```java
@Override
public void init() throws Exception {
    ConfigurableApplicationContext context = new SpringApplicationBuilder(WebShieldApplication.class)
            .headless(false)
            .web(WebApplicationType.NONE)
            .run(getParameters().getRaw().toArray(new String[0]));
    SpringContext.setApplicationContext(context);
}
```

### 2. Active Canary Token XSS Detection (`InputReflectionAnalyzer.java`)
```java
String canary = "ws_probe_" + UUID.randomUUID().toString().substring(0, 8);
String probeUrl = replaceQueryParam(page.getUrl(), param, canary);
HttpResponseData res = context.getHttpManager().execute(HttpRequestBuilder.get(probeUrl).build(), targetDomain);

if (res != null && res.getBody() != null && res.getBody().contains(canary)) {
    results.add(new AssessmentResult("Unfiltered Parameter Reflection (XSS Indicator)", 
        "Input Handling", "WS-REF-002", probeUrl, param, "GET", Severity.HIGH, ...));
}
```

### 3. Generational MIO Evolutionary Search (`EvolutionaryTestEngine.java`)
```java
while (progress.getCurrentGeneration() < activeConfig.getMaxGenerations()
        && progress.getEvaluationsCompleted() < activeConfig.getEvaluationBudget()) {
    int gen = progress.incrementGeneration();
    CandidateSelector.SelectionChoice choice = selector.selectNextCandidate(archive, spec);
    ApiTestCase candidate = choice.candidateToEvaluate();
    EvaluationResult evalRes = safeEvaluate(activeEvaluator, candidate);
    for (SearchObjective obj : archive.getRegisteredObjectives().values()) {
        FitnessScore score = fitnessEvaluator.evaluate(obj, candidate, evalRes);
        archive.offer(obj, candidate, evalRes, score, gen);
    }
}
```

### 4. Native Google Gemini AI Client (`GeminiLlmProvider.java`)
```java
HttpRequest httpRequest = HttpRequest.newBuilder()
        .uri(URI.create(GEMINI_API_BASE + model + ":generateContent?key=" + config.apiKey().trim()))
        .header("Content-Type", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString(requestJson, StandardCharsets.UTF_8))
        .timeout(Duration.ofSeconds(30))
        .build();
HttpResponse<String> response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());
```

---

## 📜 Ethical Assessment Policy
WebShield is built strictly for authorized security auditing, defensive hardening, and educational research. Users must only scan systems they own or have explicit written permission to test.
