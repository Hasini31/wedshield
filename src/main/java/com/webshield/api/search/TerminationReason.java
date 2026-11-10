package com.webshield.api.search;

/**
 * Reason for the conclusion of an evolutionary search execution.
 */
public enum TerminationReason {
    MAX_GENERATIONS_REACHED("Reached configured maximum generation count"),
    EVALUATION_BUDGET_EXHAUSTED("Exhausted total allowed evaluation / request budget"),
    ALL_OBJECTIVES_COVERED("Successfully achieved all registered testing objectives"),
    CANCELLED("Search execution was cancelled by user or caller"),
    NO_CANDIDATES_GENERATED("Initial candidate generation produced no usable test cases"),
    ERROR("An unexpected exception terminated the search process");

    private final String description;

    TerminationReason(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
}

