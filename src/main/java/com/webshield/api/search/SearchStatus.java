package com.webshield.api.search;

/**
 * State of the evolutionary search lifecycle.
 */
public enum SearchStatus {
    NOT_STARTED,
    INITIALIZING,
    RUNNING,
    CANCELLED,
    COMPLETED,
    FAILED
}

