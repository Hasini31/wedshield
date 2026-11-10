# wedshield

WedShield is an automated website and REST API security assessment platform built with **Java 21** and **JavaFX**.

## Implemented platform capabilities

- **OpenAPI mutation fuzzing** via `OpenApiMutationFuzzer`
- **Dynamic crawling** via `DynamicCrawler`
- **OWASP-oriented vulnerability detection** via `OwaspVulnerabilityDetector`
- **Differential regression analysis** via `DifferentialRegressionAnalyzer`
- **JavaFX desktop workflow** via `WedShieldApp`

## Build and test

```bash
mvn test
```

## Run JavaFX app

```bash
mvn javafx:run
```
