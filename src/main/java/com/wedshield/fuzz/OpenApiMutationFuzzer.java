package com.wedshield.fuzz;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class OpenApiMutationFuzzer {
    private static final List<String> HTTP_VERBS = List.of("get", "post", "put", "patch", "delete");

    public List<String> generateMutations(String openApiDocument) {
        if (openApiDocument == null || openApiDocument.isBlank()) {
            return List.of();
        }

        List<String> mutations = new ArrayList<>();
        String currentPath = null;
        for (String rawLine : openApiDocument.split("\\R")) {
            String line = rawLine.strip();
            if (line.startsWith("/") && line.endsWith(":")) {
                currentPath = line.substring(0, line.length() - 1);
                continue;
            }

            if (currentPath != null) {
                for (String verb : HTTP_VERBS) {
                    if (line.toLowerCase(Locale.ROOT).startsWith(verb + ":")) {
                        mutations.add("%s %s :: oversized-string".formatted(verb.toUpperCase(Locale.ROOT), currentPath));
                        mutations.add("%s %s :: invalid-type".formatted(verb.toUpperCase(Locale.ROOT), currentPath));
                    }
                }
            }
        }

        return mutations;
    }
}
