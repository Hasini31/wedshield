package com.wedshield.fuzz;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class OpenApiMutationFuzzerTest {

    @Test
    void generatesMutationsForDocumentedOperations() {
        String openApi = """
                /pets:
                  get:
                /users:
                  post:
                """;

        List<String> mutations = new OpenApiMutationFuzzer().generateMutations(openApi);

        assertEquals(4, mutations.size());
    }
}
