package com.wedshield.model;

import java.util.Objects;

public record Finding(String id, String title, Severity severity, String description, String location) {
    public Finding {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(title, "title");
        Objects.requireNonNull(severity, "severity");
        Objects.requireNonNull(description, "description");
        Objects.requireNonNull(location, "location");
    }
}
