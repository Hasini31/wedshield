package com.webshield.api.parser;

import java.util.Collections;
import java.util.List;

/**
 * Exception thrown when parsing or extracting OpenAPI/Swagger specifications fails.
 */
public class OpenApiParseException extends RuntimeException {

    private final List<String> parserMessages;

    public OpenApiParseException(String message) {
        super(message);
        this.parserMessages = List.of(message);
    }

    public OpenApiParseException(String message, Throwable cause) {
        super(message, cause);
        this.parserMessages = List.of(message);
    }

    public OpenApiParseException(String message, List<String> parserMessages) {
        super(message + (parserMessages != null && !parserMessages.isEmpty() ? " Details: " + String.join("; ", parserMessages) : ""));
        this.parserMessages = parserMessages != null ? List.copyOf(parserMessages) : List.of();
    }

    public List<String> getParserMessages() {
        return Collections.unmodifiableList(parserMessages);
    }
}

